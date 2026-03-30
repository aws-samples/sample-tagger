#!/bin/bash

###############################################################################
# Taggr Solution - Configuration Guide
###############################################################################

CYAN='\033[0;36m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

printf "\n"
printf "${CYAN}=========================================${NC}\n"
printf "${CYAN} Taggr Solution - Configuration Guide${NC}\n"
printf "${CYAN}=========================================${NC}\n"
printf "\n"
printf "  Role chain for cross-account operations:\n"
printf "\n"
printf "  Local IAM User\n"
printf "    └─► IAMRootRoleTaggerSolution (local account)\n"
printf "          └─► IAMChildRoleTaggerSolution (remote accounts)\n"
printf "\n"
printf "${CYAN}─────────────────────────────────────────${NC}\n"
printf "${YELLOW}Step 1: Validate AWS CLI & get identity${NC}\n"
printf "${CYAN}─────────────────────────────────────────${NC}\n"
printf "\n"

if ! command -v aws &> /dev/null; then
    printf "  ${RED}✗ AWS CLI is not installed${NC}\n"
    printf "  Install: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html\n"
    exit 1
fi
printf "  ${GREEN}✓${NC} AWS CLI found\n"

if ! command -v python3 &> /dev/null; then
    printf "  ${RED}✗ Python 3 is not installed${NC}\n"
    printf "  Install Python 3.11+: https://www.python.org/downloads/\n"
    exit 1
fi
PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
PY_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]); then
    printf "  ${RED}✗ Python ${PY_VERSION} found, but 3.11+ is required${NC}\n"
    exit 1
fi
printf "  ${GREEN}✓${NC} Python ${PY_VERSION} found\n"

IDENTITY=$(aws sts get-caller-identity 2>&1)
if [ $? -ne 0 ]; then
    printf "  ${RED}✗ Failed to get caller identity. Check your AWS credentials.${NC}\n"
    exit 1
fi

AWS_ACCOUNT=$(echo "$IDENTITY" | python3 -c "import sys,json; print(json.load(sys.stdin)['Account'])")
AWS_ARN=$(echo "$IDENTITY" | python3 -c "import sys,json; print(json.load(sys.stdin)['Arn'])")

printf "  ${GREEN}✓${NC} Account : ${GREEN}${AWS_ACCOUNT}${NC}\n"
printf "  ${GREEN}✓${NC} ARN     : ${GREEN}${AWS_ARN}${NC}\n"
printf "\n"
printf "${CYAN}─────────────────────────────────────────${NC}\n"
printf "${YELLOW}Step 2: Create Root Role (local account)${NC}\n"
printf "${CYAN}─────────────────────────────────────────${NC}\n"
printf "\n"
printf "  ${GREEN}Option A - AWS CLI:${NC}\n"
printf "\n"
printf "  aws cloudformation deploy \\\\\n"
printf "    --template-file security/cloudformation.root.iam.role.yaml \\\\\n"
printf "    --stack-name TaggrRootRole \\\\\n"
printf "    --parameter-overrides PrincipalARN=\"${AWS_ARN}\" \\\\\n"
printf "    --capabilities CAPABILITY_NAMED_IAM\n"
printf "\n"
printf "  ${GREEN}Option B - AWS Console:${NC}\n"
printf "\n"
printf "  1. Go to CloudFormation > Create stack > Upload a template file\n"
printf "  2. Upload: security/cloudformation.root.iam.role.yaml\n"
printf "  3. Stack name: TaggrRootRole\n"
printf "  4. Parameter PrincipalARN: ${AWS_ARN}\n"
printf "  5. Check 'I acknowledge that AWS CloudFormation might create IAM resources'\n"
printf "  6. Create stack\n"
printf "\n"
printf "${CYAN}─────────────────────────────────────────${NC}\n"
printf "${YELLOW}Step 3: Create Child Role (target accounts)${NC}\n"
printf "${CYAN}─────────────────────────────────────────${NC}\n"
printf "\n"
printf "  ${GREEN}Option A - AWS CLI:${NC}\n"
printf "\n"
printf "  aws cloudformation deploy \\\\\n"
printf "    --template-file security/cloudformation.child.iam.role.yaml \\\\\n"
printf "    --stack-name TaggrChildRole \\\\\n"
printf "    --parameter-overrides RoleARN=\"arn:aws:iam::${AWS_ACCOUNT}:role/IAMRootRoleTaggerSolution\" \\\\\n"
printf "    --capabilities CAPABILITY_NAMED_IAM\n"
printf "\n"
printf "  ${GREEN}Option B - AWS Console:${NC}\n"
printf "\n"
printf "  1. Go to CloudFormation > Create stack > Upload a template file\n"
printf "  2. Upload: security/cloudformation.child.iam.role.yaml\n"
printf "  3. Stack name: TaggrChildRole\n"
printf "  4. Parameter RoleARN: arn:aws:iam::${AWS_ACCOUNT}:role/IAMRootRoleTaggerSolution\n"
printf "  5. Check 'I acknowledge that AWS CloudFormation might create IAM resources'\n"
printf "  6. Create stack\n"
printf "\n"
printf "  Run this in each target account where you want to tag resources.\n"
printf "\n"
printf "${CYAN}─────────────────────────────────────────${NC}\n"
printf "${YELLOW}Step 4: Run the application${NC}\n"
printf "${CYAN}─────────────────────────────────────────${NC}\n"
printf "\n"
printf "  ./start.sh\n"
printf "\n"
printf "${CYAN}=========================================${NC}\n"
printf "\n"
