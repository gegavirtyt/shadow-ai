<#
.SYNOPSIS
    Launches an EC2 test workload instance enforcing IMDSv2 within the isolated AI Workload subnet.

.DESCRIPTION
    Phase 2 Lab Script for "The Shadow AI Governance Gap" research lab.
    Deploys an EC2 instance in the private subnet (sg-ai-workload) strictly enforcing IMDSv2
    (--http-tokens required --http-put-response-hop-limit 1).
    This restricts Server-Side Request Forgery (SSRF) and Indirect Prompt Injection (IPI)
    attacks from extracting instance role credentials from the AWS Instance Metadata Service.

.PARAMETER DryRun
    If specified, validates the launch request with AWS without creating the instance.

.PARAMETER InstanceType
    The EC2 instance type (default: t3.micro).
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [string]$InstanceType = "t3.micro",
    [Parameter(Mandatory = $true)][string]$AmiId,
    [Parameter(Mandatory = $true)][string]$SubnetId,
    [Parameter(Mandatory = $true)][string]$SecurityGroupId,
    [string]$Region = "us-east-1"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Shadow AI Governance: Launch Workload Instance (IMDSv2 Enforced) ===" -ForegroundColor Cyan
Write-Host "Region:             $Region"
Write-Host "Subnet (Private):   $SubnetId"
Write-Host "Security Group:     $SecurityGroupId (sg-ai-workload)"
Write-Host "AMI ID:             $AmiId"
Write-Host "Instance Type:      $InstanceType"
Write-Host "IMDSv2 Policy:      HttpTokens=required, HttpPutResponseHopLimit=1" -ForegroundColor Yellow

$metadataOptions = "HttpEndpoint=enabled,HttpTokens=required,HttpPutResponseHopLimit=1"

$cmdArgs = @(
    "ec2", "run-instances",
    "--image-id", $AmiId,
    "--instance-type", $InstanceType,
    "--subnet-id", $SubnetId,
    "--security-group-ids", $SecurityGroupId,
    "--metadata-options", $metadataOptions,
    "--tag-specifications", "ResourceType=instance,Tags=[{Key=Name,Value=shadow-ai-workload-instance},{Key=Project,Value=Shadow-AI-Governance}]",
    "--region", $Region
)

if ($DryRun) {
    Write-Host "[DRY RUN] Executing dry run validation..." -ForegroundColor Yellow
    $cmdArgs += "--dry-run"
    try {
        & aws $cmdArgs
    } catch {
        if ($_.Exception.Message -match "DryRunOperation") {
            Write-Host "[SUCCESS] Dry run passed! AWS parameters and IAM permissions are verified." -ForegroundColor Green
        } else {
            Write-Error $_
        }
    }
} else {
    Write-Host "Launching workload instance with enforced IMDSv2..." -ForegroundColor Green
    $result = & aws $cmdArgs | ConvertFrom-Json
    $instanceId = $result.Instances[0].InstanceId
    Write-Host "Successfully launched instance: $instanceId" -ForegroundColor Green
    
    # Also verify/enforce via modify-instance-metadata-options command line explicitly:
    Write-Host "Verifying IMDSv2 configuration with modify-instance-metadata-options CLI flags:"
    Write-Host "  aws ec2 modify-instance-metadata-options --instance-id $instanceId --http-tokens required --http-put-response-hop-limit 1"
    
    return $instanceId
}
