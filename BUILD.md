# DXC SSM Certificate Authority Build and Install

## Requirements

 - Eclipse with Maven
 - Docker (Docker desktop if using Windows)
 - AWS Account
 
## Build

 1- Clone the contents of this repository
 2- Import the project in Eclipse or create a project on the path where the repository was cloned, with Maven personality
 3- Create a Maven Run Configuration, with target "install"
 4- Execute the run configuration

A successful build will provide under the `target` directory
 - A ZIP containing the deployment package
 - A customized AWS CloudFormation template providing the required SSM Automation documents, customized for the generated
   deployment package.

## Install

**WARNING** If you rebuild the package you must run through these steps again

  1- Copy the deployment package to an AWS S3 bucket **in the same region** where you'll deploy the AWS SSM Automations
  2- In the same region where the bucket exists, create a new AWS CloudFormation stack using the template provided
     in the `target` folder.