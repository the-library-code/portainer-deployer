# TLC: Deploying stacks to Zenit

This document gives instructions for installing and using the customised version of `portainer-deployer` which adds
the additional functionality for managing portainer stacks and docker resources:

1. Secrets can be created in the Docker engine, either individual or parsed from stack YAML
2. Networks can be created in the Docker engine, either individual or parsed from stack YAML
3. Stacks can be deployed in **swarm** mode (previously just compose mode was supported)
4. Key/val replacements (useful when deploying specific tags) allow hyphens in key and values
5. After resources or stacks created, optionally set the resource controls so that they're owned by the given team

These customisations are made to help support the kinds of stack management tasks needed at TLC to set up new customer
environments and for CI/CD to redeploy stacks as needed

## Install and set up portainer-deployer

1. Get from git: `git clone git@github.com:the-library-code/portainer-deployer.git`
2. Copy and rename the example config to a new place, e.g. `cp portainer_deployer/app.conf.example /home/developer/deployer.conf`
3. Edit this configuration for your local portainer stack, or Zenit, or so on:
   1. URL for Zenit should be `https://maintenance.the-library-cloud.de`
   2. See the central password DB for `TLC Portainer API Token` to set the username and token secret
     * When you are logged in into portainer and click on your user name and on `my account`. Then you can create access tokens.
4. Install the Python module. Use virtual environment if desired. Install with `python setup.py install`
5. Install requirements using e.g. `pip wheel -r requirements.txt`
6. Set the configuration path to your custom config
   1. For example: `portainer-deployer config --config-path /home/developer/deployer.conf`

In Gitlab CI/CD we use variables for the configuration of the deployer. In the container there is a script
`entrypoint.sh` that uses sed to push the values from the enviroment variables `PORTAINER_URL`, `PORTAINER_USER`,
and `PORTAINER_TOKEN` into the configuration file. Other environment variables are used by CI/CD to build the deploy
command.

## Create resources

If this is a new environment or customer, some networks, volumes and secrets will need to be created before the full 
stack can be deployed. You will see an error during deployment if some secrets, volumes or networks referenced in the 
stack YAML are not already present.

The recommended way to do this is to let the deployer script parse the YAML for the stack, and automatically create
resources with the right settings and permissions for use in our swarm stacks.

Each of these `create <secret|network|volume>` subcommands expect `--team TLC` (if "TLC" is the team name to own the
resource) and `--endpoint <ID>` (4 for Zenit swarm) and `--path /path/to/yaml.yml`

If the team is missing, the resource will be owned only by the creating user.

If the path is missing, the script will expect to create individual named resources instead.

### Create secrets

*Reminder*: Zenit endpoint ID is **4**, your local portainer environment probably uses different ID numbers!

The only "secret-specific" arguments to worry about here is `--length` to set the string length of the randomly
 generated secret. The default is 20.

1. Make sure you have a good copy of the latest (or preferred) stack YAML. In CI/CD this will be the `main` branch. 
2. Run the create command with a path: `portainer-deployer create secret --endpoint 4 --team TLC --path /path/to/stack-backend.yml --length 20`

You can create individual secrets with the `--name` and `--value` arguments instead of `--path`

### Create networks

The only "network-specific" arguments to worry about here are:
* `--driver <overlay|host|bridge>` to set the network driver. This defaults to "overlay", since that is what external
 networks in our swarms use.
* `--attachable <true|false>` to allow containers to attach to this network (or not)
* `--internal` to make this network internal only (typically not needed for our purposes), note no arg here, just leave
 it out to force external 
* `--dedup <truef|false>` to skip creation if existing networks of the same name already exist. Default: true

1. Make sure you have a good copy of the latest (or preferred) stack YAML. In CI/CD this will be the `main` branch. 
2. Run the create command with a path: `portainer-deployer create network --endpoint 4 --team TLC --path /path/to/stack-backend.yml`

You can create individual networks with the `--name` argument instead of `--path`

### Create volumes

There are no "volume-specific" arguments to worry about here.

1. Make sure you have a good copy of the latest (or preferred) stack YAML. In CI/CD this will be the `main` branch. 
2. Run the create command with a path: `portainer-deployer create volume --endpoint 4 --team TLC --path /path/to/stack-backend.yml`

You can create individual volumes with the `--name` argument instead of `--path`

## Deploy and redeploy Stack

Most of the deployment functionality offered by the original **portainer-deployer** code is used here, but this branch
adds the ability to specify swarm stacks rather than only supporting compose stacks. Without this, the API will complain
that the networks, secrets and volumes are inaccessible.

Make sure that your config has `stack_type = swarm`. This is on in the example file provided.

**Tag references**: Our CI/CD usually wants to give a specific image tag when deploying a new stack. The `--update-keys`
argument here is a useful tool, to modify the plain YAML we get from Git by altering the `image` references to point to 
specific tags or image versions.

**Redeployment**: If `--redeploy -y` is in the args, the script will look for and delete an existing stack of that name
before deploying. It's fine to include this even if the stack doesn't exist yet. If `-y` is not present, you will be
prompted for confirmation before deleting/redeploying.

You **must** specify a stack name.

### Deploy plain (no tag, main branch) stack 

1. Make sure you have a good copy of the latest (or preferred) stack YAML. In CI/CD this will be the `main` branch. 
2. Run the create command with a path: `portainer-deployer deploy --redeploy --name fhnw-ds7-backend --endpoint 4 --team TLC --path /path/to/fhnw-backend.yml`

### Deploy specific tag / image version

Say, the stack is `fhnw-ds7-backend` and you want the docker image: `hub.lib-co.de/tlc/dspace-hosting/fhnw-ds7:backend-fhnw-ds7-test-20230101-01` 

1. Make sure you have a good copy of the latest (or preferred) stack YAML. In CI/CD this will be the `main` branch. 
2. Run the create command with a path and key updates: `portainer-deployer deploy --redeploy --name fhnw-ds7-backend --endpoint 4 --team TLC --path /path/to/fhnw-backend.yml --update-keys "services.dspace-test.image"="hub.lib-co.de/tlc/dspace-hosting/fhnw-ds7:backend-fhnw-ds7-test-20230101-01"`

**Quoting**: I recommend quoting the key / value pairs so that any environment variables used to reference the image name and version don't break things.

## All other commands

All the other commands and functionality should work as per the [README.md](README.md)
