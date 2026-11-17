# Reads the outputs of infra/base (network, database, password parameter)
# from its state file, which sits next to this folder on the same computer.

data "terraform_remote_state" "base" {
  backend = "local"

  config = {
    path = "${path.module}/../base/terraform.tfstate"
  }
}

locals {
  base = data.terraform_remote_state.base.outputs
}
