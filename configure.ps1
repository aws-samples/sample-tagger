###############################################################################
# Taggr Solution - Configuration Guide (Windows PowerShell)
###############################################################################

$CYAN = "`e[36m"
$YELLOW = "`e[33m"
$GREEN = "`e[32m"
$RED = "`e[31m"
$NC = "`e[0m"

Write-Host ""
Write-Host "${CYAN}=========================================${NC}"
Write-Host "${CYAN} Taggr Solution - Configuration Guide${NC}"
Write-Host "${CYAN}=========================================${NC}"
Write-Host ""
Write-Host "  Role chain for cross-account operations:"
Write-Host ""
Write-Host "  Local IAM User"
Write-Host "    +-- IAMRootRoleTaggerSolution (local account)"
Write-Host "          +-- IAMChildRoleTaggerSolution (remote accounts)"
Write-Host ""
Write-Host "${CYAN}-----------------------------------------${NC}"
Write-Host "${YELLOW}Step 1: Validate AWS CLI & get identity${NC}"
Write-Host "${CYAN}-----------------------------------------${NC}"
Write-Host ""

# Check AWS CLI
if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    Write-Host "  ${RED}x AWS CLI is not installed${NC}"
    Write-Host "  Install: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
    exit 1
}
Write-Host "  ${GREEN}ok${NC} AWS CLI found"

# Check Python
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "  ${RED}x Python is not installed${NC}"
    Write-Host "  Install Python 3.11+: https://www.python.org/downloads/"
    exit 1
}
$pyVersion = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$pyMajor = python -c "import sys; print(sys.version_info.major)"
$pyMinor = python -c "import sys; print(sys.version_info.minor)"
if ([int]$pyMajor -lt 3 -or ([int]$pyMajor -eq 3 -and [int]$pyMinor -lt 11)) {
    Write-Host "  ${RED}x Python $pyVersion found, but 3.11+ is required${NC}"
    exit 1
}
Write-Host "  ${GREEN}ok${NC} Python $pyVersion found"

# Get caller identity
try {
    $identityJson = aws sts get-caller-identity 2>&1
    $identity = $identityJson | ConvertFrom-Json
    $AWS_ACCOUNT = $identity.Account
    $AWS_ARN = $identity.Arn
} catch {
    Write-Host "  ${RED}x Failed to get caller identity. Check your AWS credentials.${NC}"
    exit 1
}

Write-Host "  ${GREEN}ok${NC} Account : ${GREEN}$AWS_ACCOUNT${NC}"
Write-Host "  ${GREEN}ok${NC} ARN     : ${GREEN}$AWS_ARN${NC}"
Write-Host ""
Write-Host "${CYAN}-----------------------------------------${NC}"
Write-Host "${YELLOW}Step 2: Create Root Role (local account)${NC}"
Write-Host "${CYAN}-----------------------------------------${NC}"
Write-Host ""
Write-Host "  ${GREEN}Option A - AWS CLI:${NC}"
Write-Host ""
Write-Host "  aws cloudformation deploy ``"
Write-Host "    --template-file security/cloudformation.root.iam.role.yaml ``"
Write-Host "    --stack-name TaggrRootRole ``"
Write-Host "    --parameter-overrides PrincipalARN=`"$AWS_ARN`" ``"
Write-Host "    --capabilities CAPABILITY_NAMED_IAM"
Write-Host ""
Write-Host "  ${GREEN}Option B - AWS Console:${NC}"
Write-Host ""
Write-Host "  1. Go to CloudFormation > Create stack > Upload a template file"
Write-Host "  2. Upload: security/cloudformation.root.iam.role.yaml"
Write-Host "  3. Stack name: TaggrRootRole"
Write-Host "  4. Parameter PrincipalARN: $AWS_ARN"
Write-Host "  5. Check 'I acknowledge that AWS CloudFormation might create IAM resources'"
Write-Host "  6. Create stack"
Write-Host ""
Write-Host "${CYAN}-----------------------------------------${NC}"
Write-Host "${YELLOW}Step 3: Create Child Role (target accounts)${NC}"
Write-Host "${CYAN}-----------------------------------------${NC}"
Write-Host ""
Write-Host "  ${GREEN}Option A - AWS CLI:${NC}"
Write-Host ""
Write-Host "  aws cloudformation deploy ``"
Write-Host "    --template-file security/cloudformation.child.iam.role.yaml ``"
Write-Host "    --stack-name TaggrChildRole ``"
Write-Host "    --parameter-overrides RoleARN=`"arn:aws:iam::${AWS_ACCOUNT}:role/IAMRootRoleTaggerSolution`" ``"
Write-Host "    --capabilities CAPABILITY_NAMED_IAM"
Write-Host ""
Write-Host "  ${GREEN}Option B - AWS Console:${NC}"
Write-Host ""
Write-Host "  1. Go to CloudFormation > Create stack > Upload a template file"
Write-Host "  2. Upload: security/cloudformation.child.iam.role.yaml"
Write-Host "  3. Stack name: TaggrChildRole"
Write-Host "  4. Parameter RoleARN: arn:aws:iam::${AWS_ACCOUNT}:role/IAMRootRoleTaggerSolution"
Write-Host "  5. Check 'I acknowledge that AWS CloudFormation might create IAM resources'"
Write-Host "  6. Create stack"
Write-Host ""
Write-Host "  Run this in each target account where you want to tag resources."
Write-Host ""
Write-Host "${CYAN}-----------------------------------------${NC}"
Write-Host "${YELLOW}Step 4: Run the application${NC}"
Write-Host "${CYAN}-----------------------------------------${NC}"
Write-Host ""
Write-Host "  .\start.ps1"
Write-Host ""
Write-Host "${CYAN}=========================================${NC}"
Write-Host ""
