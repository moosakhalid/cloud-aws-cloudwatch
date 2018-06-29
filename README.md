# AWS - Generic CloudWatch Opspack

Amazon Web Services (AWS) is a secure cloud services platform, offering compute power, database storage, content delivery and other functionality to help businesses scale and grow. Millions of customers are currently leveraging AWS cloud products and solutions to build sophisticated applications with increased flexibility, scalability and reliability.

# What Can You Monitor

Opsview Monitor's AWS Generic Cloudwatch Opspack provides an easy way to monitor AWS and all of your custom Cloudwatch metrics. You can easily tie these custom service checks into the larger picture of your infrastructure for a complete view of your AWS environment.

Note: This Opspack knows when it was last run, so when testing the results in the troubleshoot section, you will need to wait a couple minutes each time you recheck the results. The time frame that is searched for is based around the last time the Opspack ran, so running it too quickly will result in no data being found and the service check going into an unknown

## Service Checks

| Service Check | Description |
|:------------- |:----------- |
|AWSCloudWatch/Generic.CPUReservation | The percentage of CPU units that are reserved by running tasks in the cluster.
|AWSCloudWatch/Generic.CPUUtilization | The percentage of CPU utilization
|AWSCloudWatch/Generic.MemoryReservation | The percentage of memory that is reserved by running tasks in the cluster

## Prerequisites

To be able to monitor AWS CloudWatch services you need to add your AWS credentials to your Opsview Monitor server.

We recommend adding your AWS Access Key ID and AWS Secret Key ID to the default location:

 `/opt/opsview/monitoringscripts/etc/plugins/cloud-aws/aws_credentials.cfg`

This credentials file should be in the following format:

```
[default]
aws_access_key_id = "Your Access Key Id"
aws_secret_access_key = "Your Secret Key Id"
```

If you are not using the default path, you will then need to assign your path to the variable: `AWS_CLOUDWATCH_AUTHENTICATION`.

## Setup and Configuration

To configure and utilize this Opspack, you need to add the 'Cloud - AWS - CloudWatch' Opspack to your Opsview Monitor system.

#### Step 1: Add the host template

![Add host template](/docs/img/add_aws_generic_host.png?raw=true)

#### Step 2: Add and configure the variables for the host

* `AWS_CLOUDWATCH_AUTHENTICATION` - Contains either the file location created earlier (recommended method) or add the Access Key and Secret Key directly to this variable's values.

* Override the Region value if you are not using the default

![Add credentials variable](/docs/img/add_aws_credentials_variable.png?raw=true)

* `AWS_CLOUDWATCH_GENERIC_SEARCH` - Specify the AWS CloudWatch metric you want to monitor (e.g. CPUUtilization, CPUReservation, MemoryReservation)

#### Step 3:  Reload and view the statistics

![View output](/docs/img/view_aws_generic_service_checks.png?raw=true)
