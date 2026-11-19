# provision_lab.ps1 - Automated AWS Lab Provisioning for Shadow AI Governance Research
#
# Creates the proxy and workload security groups inside an EXISTING VPC. All
# account-specific identifiers are parameters; nothing here is tied to one account.
# Example:
#   ./provision_lab.ps1 -VpcId vpc-0123 -PublicSubnetId subnet-aaa -PrivateSubnetId subnet-bbb `
#       -InternetGatewayId igw-ccc -RouteTableId rtb-ddd -TrustedIp 203.0.113.10/32
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$VpcId,
    [Parameter(Mandatory = $true)][string]$PublicSubnetId,
    [Parameter(Mandatory = $true)][string]$PrivateSubnetId,
    [Parameter(Mandatory = $true)][string]$InternetGatewayId,
    [Parameter(Mandatory = $true)][string]$RouteTableId,
    [Parameter(Mandatory = $true)][string]$TrustedIp,
    [string]$Region = "us-east-1",
    [string]$OutputPath = (Join-Path $PSScriptRoot "resources.json")
)
$ErrorActionPreference = "Stop"

Write-Host "=== Phase 2: Provisioning AWS Lab Infrastructure ===" -ForegroundColor Cyan

$trustedIp = $TrustedIp
$region = $Region
$vpcId = $VpcId
$pubSubnetId = $PublicSubnetId
$privSubnetId = $PrivateSubnetId
$igwId = $InternetGatewayId
$rtId = $RouteTableId

Write-Host "Existing VPC: $vpcId"
Write-Host "Existing Public Subnet: $pubSubnetId"
Write-Host "Existing Private Subnet: $privSubnetId"
Write-Host "Existing IGW: $igwId"
Write-Host "Existing Route Table: $rtId"

# 4. Create Security Groups
Write-Host "[4/5] Creating Security Groups..."
# GroupName cannot start with 'sg-' in AWS EC2 API, but tag:Name is 'sg-ai-proxy'
$sgProxyJson = aws ec2 create-security-group `
    --group-name "shadow-ai-proxy" `
    --description "Proxy Gateway Security Group - Inbound 8080 from trusted IP, full outbound" `
    --vpc-id $vpcId `
    --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=sg-ai-proxy},{Key=Role,Value=Proxy-Gateway}]" `
    --region $region | ConvertFrom-Json
$sgProxyId = $sgProxyJson.GroupId
Write-Host "  -> sg-ai-proxy Created: $sgProxyId" -ForegroundColor Green

# Inbound 8080 from trusted IP
aws ec2 authorize-security-group-ingress `
    --group-id $sgProxyId `
    --protocol tcp `
    --port 8080 `
    --cidr $trustedIp `
    --region $region | Out-Null
Write-Host "  -> sg-ai-proxy: Allowed TCP 8080 from trusted IP ($trustedIp)" -ForegroundColor Green

# 'sg-ai-workload' (GroupName: shadow-ai-workload, Name tag: sg-ai-workload)
$sgWorkloadJson = aws ec2 create-security-group `
    --group-name "shadow-ai-workload" `
    --description "AI Workload Security Group - Deny direct internet, outbound TCP 8080 ONLY to sg-ai-proxy" `
    --vpc-id $vpcId `
    --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=sg-ai-workload},{Key=Role,Value=AI-Workload}]" `
    --region $region | ConvertFrom-Json
$sgWorkloadId = $sgWorkloadJson.GroupId
Write-Host "  -> sg-ai-workload Created: $sgWorkloadId" -ForegroundColor Green

# Allow inbound 8080 on sg-ai-proxy from sg-ai-workload
aws ec2 authorize-security-group-ingress `
    --group-id $sgProxyId `
    --protocol tcp `
    --port 8080 `
    --source-group $sgWorkloadId `
    --region $region | Out-Null
Write-Host "  -> sg-ai-proxy: Allowed TCP 8080 from sg-ai-workload ($sgWorkloadId)" -ForegroundColor Green

# In sg-ai-workload: Revoke default outbound rule (0.0.0.0/0)
$workloadDesc = aws ec2 describe-security-groups --group-ids $sgWorkloadId --region $region | ConvertFrom-Json
$defaultEgress = $workloadDesc.SecurityGroups[0].IpPermissionsEgress
if ($defaultEgress) {
    aws ec2 revoke-security-group-egress `
        --group-id $sgWorkloadId `
        --ip-permissions ($defaultEgress | ConvertTo-Json -Depth 5) `
        --region $region | Out-Null
    Write-Host "  -> sg-ai-workload: Revoked default 0.0.0.0/0 outbound" -ForegroundColor Green
}

# Permit outbound TCP 8080 ONLY to 'sg-ai-proxy'
aws ec2 authorize-security-group-egress `
    --group-id $sgWorkloadId `
    --protocol tcp `
    --port 8080 `
    --source-group $sgProxyId `
    --region $region | Out-Null
Write-Host "  -> sg-ai-workload: Allowed outbound TCP 8080 ONLY to sg-ai-proxy ($sgProxyId)" -ForegroundColor Green

# Save metadata (generated, environment-specific; git-ignored)
$resources = @{
    Region = $region
    VpcId = $vpcId
    PublicSubnetId = $pubSubnetId
    PrivateSubnetId = $privSubnetId
    InternetGatewayId = $igwId
    PublicRouteTableId = $rtId
    SgProxyId = $sgProxyId
    SgWorkloadId = $sgWorkloadId
    TrustedIp = $trustedIp
}
$resources | ConvertTo-Json -Depth 4 | Set-Content -Path $OutputPath -Encoding utf8
Write-Host "Infrastructure resources saved to $OutputPath" -ForegroundColor Cyan
