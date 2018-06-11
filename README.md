
# AWS - Generic CloudWatch Opspack

Amazon Web Services (AWS) is a secure cloud services platform, offering compute power, database storage, content delivery and other functionality to help businesses scale and grow. Millions of customers are currently leveraging AWS cloud products and solutions to build sophisticated applications with increased flexibility, scalability and reliability.

# What Can You Monitor

Opsview Monitor's AWS Generic Cloudwatch Opspack provides an easy way to monitor AWS and all of your custom Cloudwatch metrics. You can easily tie these custom service checks into the larger picture of your infrastructure for a complete view of your AWS environment.

## Service Checks

| Service Check | Description |
|:------------- |:----------- |
|AWSCloudWatch/Generic.CPUReservation | The percentage of CPU units that are reserved by running tasks in the cluster.
|AWSCloudWatch/Generic.CPUUtilization | The percentage of CPU utilization
|AWSCloudWatch/Generic.MemoryReservation | The percentage of memory that is reserved by running tasks in the cluster
## Notes

This Opspack knows when it was last run, so when testing the results in the troubleshoot section, you will need to wait a couple minutes each time you recheck the results. The time frame that is searched for is based around the last time the Opspack ran, so running it too quickly will result in no data being found and the service check going into an unknown.

## Prerequisites

There are two ways of adding your authentication credentials to the host. We recommend adding the access key and secret key directly using the variable 'AWS_CLOUDWATCH_AUTHENTICATION'. You can also add the access key and secret key to a file (default /usr/local/nagios/etc/aws_credentials.cfg) in the following format:

```
[default]
aws_access_key_id = "Your Access Key Id"
aws_secret_access_key = "Your Secret Key Id"
```

## Setup and Configuration

Step 1: Add the host template and the 'Cloud - AWS - CloudWatch' Opspack to the host running the AWS software.

![Add host template](/docs/img/host-template.png?raw=true)

Step 2: Add and configure the host Variables tab, add in "AWS_CLOUDWATCH_AUTHENTICATION" with either the file location or the access key and secret key depending on your preferred way of supplying the access credential. Add the region you hosted in. Then add and configure the 'AWS_CLOUDWATCH_SEARCH_NAME' by adding the instance name or ID.

![Add variable](/docs/img/variable.png?raw=true)

Step 3:  Reload and view the statistics

![View output](/docs/img/output.png?raw=true)
