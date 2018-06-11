// Copyright (C) 2003-2018 Opsview Limited. All rights reserved
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"crypto/md5"
	"fmt"
	"github.com/ajgb/go-plugin"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/ec2"
	"io/ioutil"
	"os"
	"strconv"
	"syscall"
	"time"
)

var sess *session.Session
var check *plugin.Plugin
var svc *cloudwatch.CloudWatch

var opts struct {
	HostAddress   string `short:"a" long:"address" description:"Address of instance"`
	Mode          string `short:"m" long:"mode" description:"Mode" required:"true"`
	Warning       string `short:"w" long:"warning" description:"Warning"`
	Critical      string `short:"c" long:"critical" description:"Critical"`
	AccessKey     string `short:"A" long:"accesskey" description:"Access Key credential"`
	SecretKey     string `short:"S" long:"secretkey" description:"Secret Key credential"`
	FilePath      string `short:"f" long:"filepath" description:"AWS Access credentials file"`
	Region        string `short:"r" long:"region" description:"Region of AWS" default:"eu-west-1"`
	SearchName    string `short:"i" long:"searchvalue" description:"Name or ID to be monitored"`
	Statistics    string `short:"s" long:"statistics" description:"Metric type(average, minimal, maximum)" default:"average"`
	NameSpace     string `short:"n" long:"namespace" description:"The Name of the area in which the metrics are taken from(AWS/EC2, AWS/S3)"`
	DimensionName string `short:"d" long:"dimensionname" description:"The name of the value type(instanceid)"`
	DebugMode     bool   `short:"v" long:"debugmode" description:"Turns on debugging messages"`
	Pedantic      bool   `short:"p" long:"pedantic"  description:"Warn if the public DNS name does not match the instance name"`
}

func main() {
	check = checkPlugin()
	defer check.Final()
	check.AllMetricsInOutput = true

	var err error

	if err = check.ParseArgs(&opts); err != nil {
		check.ExitCritical("Error parsing arguments: %s", err)
	}
	validateArgs(check)

	var creds *credentials.Credentials

	if opts.AccessKey == "" || opts.SecretKey == "" { //If accessKey or secretKey not being used presume we should use session config file
		os.Setenv("AWS_PROFILE", opts.FilePath)
		creds = credentials.NewSharedCredentials(opts.FilePath, "default")
	} else {
		creds = credentials.NewStaticCredentials(opts.AccessKey, opts.SecretKey, "")
	}
	conf := aws.Config{
		Credentials: creds,
		Region:      aws.String(opts.Region),
	}
	sess, err = session.NewSessionWithOptions(session.Options{Config: conf})

	if err != nil {
		check.ExitUnknown("Failed to create session. Check your AWS Access Key and Secret Key.")
	}

	svc = cloudwatch.New(sess)
	if svc == nil {
		check.ExitUnknown("Unable to login to Cloudwatch")
	}

	var startTime time.Time
	// If no time is given then defaults to 300.
	endTime := time.Now()
	lastServiceCheck := updateTimeState(endTime.String())

	if lastServiceCheck == "" {
		startTime = *aws.Time(endTime.UTC().Add(time.Second * -300))
		if opts.DebugMode {
			fmt.Println("No Last Service Check time availible, defaulting to 5 minutes")
		}
	} else {
		lastServiceCheckTime, err := time.Parse("2006-01-02 15:04:05 -0700 MST", lastServiceCheck)
		if err != nil {
			check.ExitCritical("Time parsed from file is not in the correct format, " + err.Error())
		}
		startTime = *aws.Time(lastServiceCheckTime)
	}

	period := int(endTime.Sub(startTime).Seconds())

	// Works out the check period to only make a call for one datapoint. Must be a multiple of 60 (1 min)
	var periodCheck int
	if period%60 == 0 {
		periodCheck = period
	} else {
		noOfMins := period / 60
		periodCheck = noOfMins * 60
	}

	if periodCheck < 60 {
		periodCheck = 60
	}

	// Adding delay of 5 mins to match the delay in AWS
	endTime = endTime.Add(time.Second * -600)

	startTime = *aws.Time(endTime.UTC().Add(time.Second * time.Duration(-periodCheck)))
	if opts.DebugMode {
		fmt.Println("CheckPeriod: ", periodCheck, " Start time: ", startTime, " End time: ", endTime.UTC())
	}

	switch opts.Mode {
	case "AWS/S3.BucketSizeBytes":
		getMetricsResp(startTime, endTime, periodCheck, "BucketSizeBytes", "Average", "AWS/S3", "BucketName")
	case "AWS/S3.NumberOfObjects":
		getMetricsResp(startTime, endTime, periodCheck, "NumberOfObjects", "Average", "AWS/S3", "BucketName")
	case "AWS/S3.AllRequests":
		getMetricsResp(startTime, endTime, periodCheck, "AllRequests", "Sum", "AWS/S3", "BucketName")
	case "AWS/S3.GetRequest":
		getMetricsResp(startTime, endTime, periodCheck, "GetRequest", "Sum", "AWS/S3", "BucketName")
	case "AWS/S3.PutRequests":
		getMetricsResp(startTime, endTime, periodCheck, "PutRequests", "Sum", "AWS/S3", "BucketName")
	case "AWS/S3.DeleteRequests":
		getMetricsResp(startTime, endTime, periodCheck, "DeleteRequests", "Sum", "AWS/S3", "BucketName")
	case "AWS/S3.HeadRequests":
		getMetricsResp(startTime, endTime, periodCheck, "HeadRequests", "Sum", "AWS/S3", "BucketName")
	case "AWS/S3.PostRequests":
		getMetricsResp(startTime, endTime, periodCheck, "PostRequests", "Sum", "AWS/S3", "BucketName")
	case "AWS/S3.ListRequests":
		getMetricsResp(startTime, endTime, periodCheck, "ListRequests", "Sum", "AWS/S3", "BucketName")
	case "AWS/S3.BytesDownloaded":
		getMetricsResp(startTime, endTime, periodCheck, "BytesDownloaded", "Average", "AWS/S3", "BucketName")
	case "AWS/S3.BytesUploaded":
		getMetricsResp(startTime, endTime, periodCheck, "BytesUploaded", "Average", "AWS/S3", "BucketName")
	case "AWS/S3.4xxErrors":
		getMetricsResp(startTime, endTime, periodCheck, "4xxErrors", "Average", "AWS/S3", "BucketName")
	case "AWS/S3.5xxErrors":
		getMetricsResp(startTime, endTime, periodCheck, "5xxErrors", "Average", "AWS/S3", "BucketName")
	case "AWS/S3.FirstByteLatency":
		getMetricsResp(startTime, endTime, periodCheck, "FirstByteLatency", "Average", "AWS/S3", "BucketName")
	case "AWS/S3.TotalRequestLatency":
		getMetricsResp(startTime, endTime, periodCheck, "TotalRequestLatency", "Average", "AWS/S3", "BucketName")
	case "AWS/EC2.CPUCreditUsage":
		getMetricsResp(startTime, endTime, periodCheck, "CPUCreditUsage", "Average", "AWS/EC2", "InstanceId")
	case "AWS/EC2.CPUCreditBalance":
		getMetricsResp(startTime, endTime, periodCheck, "CPUCreditBalance", "Average", "AWS/EC2", "InstanceId")
	case "AWS/EC2.CPUUtilization":
		getMetricsResp(startTime, endTime, periodCheck, "CPUUtilization", "Average", "AWS/EC2", "InstanceId")
	case "AWS/EC2.DiskReadOps":
		getMetricsResp(startTime, endTime, periodCheck, "DiskReadOps", "Average", "AWS/EC2", "InstanceId")
	case "AWS/EC2.DiskWriteOps":
		getMetricsResp(startTime, endTime, periodCheck, "DiskWriteOps", "Average", "AWS/EC2", "InstanceId")
	case "AWS/EC2.DiskReadBytes":
		getMetricsResp(startTime, endTime, periodCheck, "DiskReadBytes", "Average", "AWS/EC2", "InstanceId")
	case "AWS/EC2.DiskWriteBytes":
		getMetricsResp(startTime, endTime, periodCheck, "DiskWriteBytes", "Average", "AWS/EC2", "InstanceId")
	case "AWS/EC2.NetworkIn":
		getMetricsResp(startTime, endTime, periodCheck, "NetworkIn", "Average", "AWS/EC2", "InstanceId")
	case "AWS/EC2.NetworkOut":
		getMetricsResp(startTime, endTime, periodCheck, "NetworkOut", "Average", "AWS/EC2", "InstanceId")
	case "AWS/EC2.NetworkPacketsIn":
		getMetricsResp(startTime, endTime, periodCheck, "NetworkPacketsIn", "Average", "AWS/EC2", "InstanceId")
	case "AWS/EC2.NetworkPacketsOut":
		getMetricsResp(startTime, endTime, periodCheck, "NetworkPacketsOut", "Average", "AWS/EC2", "InstanceId")
	case "AWS/EC2.Network":
		getMetricsResp(startTime, endTime, periodCheck, "NetworkIn", "Average", "AWS/EC2", "InstanceId")
		getMetricsResp(startTime, endTime, periodCheck, "NetworkOut", "Average", "AWS/EC2", "InstanceId")
		getMetricsResp(startTime, endTime, periodCheck, "NetworkPacketsIn", "Average", "AWS/EC2", "InstanceId")
		getMetricsResp(startTime, endTime, periodCheck, "NetworkPacketsOut", "Average", "AWS/EC2", "InstanceId")
	case "AWS/EC2.StatusCheckFailed":
		getMetricsResp(startTime, endTime, periodCheck, "StatusCheckFailed", "Average", "AWS/EC2", "InstanceId")
	case "AWS/ELB.BackendConnectionErrors":
		getMetricsResp(startTime, endTime, periodCheck, "BackendConnectionErrors", "Sum", "AWS/ELB", "LoadBalancerName")
	case "AWS/ELB.HealthyHostCount":
		getMetricsResp(startTime, endTime, periodCheck, "HealthyHostCount", "Average", "AWS/ELB", "LoadBalancerName")
	case "AWS/ELB.HTTPCode_Backend":
		getMetricsResp(startTime, endTime, periodCheck, "HTTPCode_Backend_2XX", "Sum", "AWS/ELB", "LoadBalancerName")
		getMetricsResp(startTime, endTime, periodCheck, "HTTPCode_Backend_3XX", "Sum", "AWS/ELB", "LoadBalancerName")
		getMetricsResp(startTime, endTime, periodCheck, "HTTPCode_Backend_4XX", "Sum", "AWS/ELB", "LoadBalancerName")
		getMetricsResp(startTime, endTime, periodCheck, "HTTPCode_Backend_5XX", "Sum", "AWS/ELB", "LoadBalancerName")
	case "AWS/ELB.HTTPCode_ELB":
		getMetricsResp(startTime, endTime, periodCheck, "HTTPCode_ELB_4XX", "Sum", "AWS/ELB", "LoadBalancerName")
		getMetricsResp(startTime, endTime, periodCheck, "HTTPCode_ELB_5XX", "Sum", "AWS/ELB", "LoadBalancerName")
	case "AWS/ELB.Latency":
		getMetricsResp(startTime, endTime, periodCheck, "Latency", "Average", "AWS/ELB", "LoadBalancerName")
	case "AWS/ELB.RequestCount":
		getMetricsResp(startTime, endTime, periodCheck, "RequestCount", "Sum", "AWS/ELB", "LoadBalancerName")
	case "AWS/ELB.SpilloverCount":
		getMetricsResp(startTime, endTime, periodCheck, "SpilloverCount", "Sum", "AWS/ELB", "LoadBalancerName")
	case "AWS/ELB.SurgeQueueLength":
		getMetricsResp(startTime, endTime, periodCheck, "SurgeQueueLength", "Maximum", "AWS/ELB", "LoadBalancerName")
	case "AWS/ELB.UnHealthyHostCount":
		getMetricsResp(startTime, endTime, periodCheck, "UnHealthyHostCount", "Average", "AWS/ELB", "LoadBalancerName")
	case "AWS/Route53.ChildHealthCheckHealthyCount":
		getMetricsResp(startTime, endTime, periodCheck, "ChildHealthCheckHealthyCount", "Average", "AWS/Route53", "HealthCheckId")
	case "AWS/Route53.ConnectionTime":
		getMetricsResp(startTime, endTime, periodCheck, "ConnectionTime", "Average", "AWS/Route53", "HealthCheckId")
	case "AWS/Route53.HealthCheckPercentageHealthy":
		getMetricsResp(startTime, endTime, periodCheck, "HealthCheckPercentageHealthy", "Average", "AWS/Route53", "HealthCheckId")
	case "AWS/Route53.HealthCheckStatus":
		getMetricsResp(startTime, endTime, periodCheck, "HealthCheckStatus", "Minimum", "AWS/Route53", "HealthCheckId")
	case "AWS/Route53.SSLHandshakeTime":
		getMetricsResp(startTime, endTime, periodCheck, "SSLHandshakeTime", "Average", "AWS/Route53", "HealthCheckId")
	case "AWS/Route53.TimeToFirstByte":
		getMetricsResp(startTime, endTime, periodCheck, "TimeToFirstByte", "Average", "AWS/Route53", "HealthCheckId")
	case "AWS/DynamoDB.ConditionalCheckFailedRequests":
		getMetricsResp(startTime, endTime, periodCheck, "ConditionalCheckFailedRequests", "Average", "AWS/DynamoDB", "TableName")
	case "AWS/DynamoDB.ConsumedReadCapacityUnits":
		getMetricsResp(startTime, endTime, periodCheck, "ConsumedReadCapacityUnits", "Average", "AWS/DynamoDB", "TableName")
	case "AWS/DynamoDB.ConsumedWriteCapacityUnits":
		getMetricsResp(startTime, endTime, periodCheck, "ConsumedWriteCapacityUnits", "Average", "AWS/DynamoDB", "TableName")
	case "AWS/DynamoDB.OnlineIndexConsumedWriteCapacity":
		getMetricsResp(startTime, endTime, periodCheck, "OnlineIndexConsumedWriteCapacity", "Average", "AWS/DynamoDB", "TableName")
	case "AWS/DynamoDB.OnlineIndexPercentageProgress":
		getMetricsResp(startTime, endTime, periodCheck, "OnlineIndexPercentageProgress", "Average", "AWS/DynamoDB", "TableName")
	case "AWS/DynamoDB.OnlineIndexThrottleEvents":
		getMetricsResp(startTime, endTime, periodCheck, "OnlineIndexThrottleEvents", "Average", "AWS/DynamoDB", "TableName")
	case "AWS/DynamoDB.ProvisionedReadCapacityUnits":
		getMetricsResp(startTime, endTime, periodCheck, "ProvisionedReadCapacityUnits", "Average", "AWS/DynamoDB", "TableName")
	case "AWS/DynamoDB.ProvisionedWriteCapacityUnits":
		getMetricsResp(startTime, endTime, periodCheck, "ProvisionedWriteCapacityUnits", "Average", "AWS/DynamoDB", "TableName")
	case "AWS/DynamoDB.ReadThrottleEvents":
		getMetricsResp(startTime, endTime, periodCheck, "ReadThrottleEvents", "Sum", "AWS/DynamoDB", "TableName")
	case "AWS/DynamoDB.ReturnedBytes":
		getMetricsResp(startTime, endTime, periodCheck, "ReturnedBytes", "Average", "AWS/DynamoDB", "TableName")
	case "AWS/DynamoDB.ReturnedItemCount":
		getMetricsResp(startTime, endTime, periodCheck, "ReturnedItemCount", "Average", "AWS/DynamoDB", "TableName")
	case "AWS/DynamoDB.ReturnedRecordsCount":
		getMetricsResp(startTime, endTime, periodCheck, "ReturnedRecordsCount", "Average", "AWS/DynamoDB", "TableName")
	case "AWS/DynamoDB.SuccessfulRequestLatency":
		getMetricsResp(startTime, endTime, periodCheck, "SuccessfulRequestLatency", "Average", "AWS/DynamoDB", "TableName")
	case "AWS/DynamoDB.SystemErrors":
		getMetricsResp(startTime, endTime, periodCheck, "SystemErrors", "Sum", "AWS/DynamoDB", "TableName")
	case "AWS/DynamoDB.ThrottledRequests":
		getMetricsResp(startTime, endTime, periodCheck, "ThrottledRequests", "Sum", "AWS/DynamoDB", "TableName")
	case "AWS/DynamoDB.UserErrors":
		getMetricsResp(startTime, endTime, periodCheck, "UserErrors", "Sum", "AWS/DynamoDB", "TableName")
	case "AWS/DynamoDB.WriteThrottleEvents":
		getMetricsResp(startTime, endTime, periodCheck, "WriteThrottleEvents", "Sum", "AWS/DynamoDB", "TableName")
	case "AWS/RDS.BinLogDiskUsage":
		getMetricsResp(startTime, endTime, periodCheck, "BinLogDiskUsage", "Average", "AWS/RDS", "DBInstanceIdentifier")
	case "AWS/RDS.CPUUtilization":
		getMetricsResp(startTime, endTime, periodCheck, "CPUUtilization", "Average", "AWS/RDS", "DBInstanceIdentifier")
	case "AWS/RDS.CPUCreditUsage":
		getMetricsResp(startTime, endTime, periodCheck, "CPUCreditUsage", "Average", "AWS/RDS", "DBInstanceIdentifier")
	case "AWS/RDS.CPUCreditBalance":
		getMetricsResp(startTime, endTime, periodCheck, "CPUCreditBalance", "Average", "AWS/RDS", "DBInstanceIdentifier")
	case "AWS/RDS.DatabaseConnections":
		getMetricsResp(startTime, endTime, periodCheck, "DatabaseConnections", "Average", "AWS/RDS", "DBInstanceIdentifier")
	case "AWS/RDS.DiskQueueDepth":
		getMetricsResp(startTime, endTime, periodCheck, "DiskQueueDepth", "Average", "AWS/RDS", "DBInstanceIdentifier")
	case "AWS/RDS.FreeableMemory":
		getMetricsResp(startTime, endTime, periodCheck, "FreeableMemory", "Average", "AWS/RDS", "DBInstanceIdentifier")
	case "AWS/RDS.FreeStorageSpace":
		getMetricsResp(startTime, endTime, periodCheck, "FreeStorageSpace", "Average", "AWS/RDS", "DBInstanceIdentifier")
	case "AWS/RDS.ReplicaLag":
		getMetricsResp(startTime, endTime, periodCheck, "ReplicaLag", "Average", "AWS/RDS", "DBInstanceIdentifier")
	case "AWS/RDS.SwapUsage":
		getMetricsResp(startTime, endTime, periodCheck, "SwapUsage", "Average", "AWS/RDS", "DBInstanceIdentifier")
	case "AWS/RDS.ReadIOPS":
		getMetricsResp(startTime, endTime, periodCheck, "ReadIOPS", "Average", "AWS/RDS", "DBInstanceIdentifier")
	case "AWS/RDS.WriteIOPS":
		getMetricsResp(startTime, endTime, periodCheck, "WriteIOPS", "Average", "AWS/RDS", "DBInstanceIdentifier")
	case "AWS/RDS.ReadLatency":
		getMetricsResp(startTime, endTime, periodCheck, "ReadLatency", "Average", "AWS/RDS", "DBInstanceIdentifier")
	case "AWS/RDS.WriteLatency":
		getMetricsResp(startTime, endTime, periodCheck, "WriteLatency", "Average", "AWS/RDS", "DBInstanceIdentifier")
	case "AWS/RDS.ReadThroughput":
		getMetricsResp(startTime, endTime, periodCheck, "ReadThroughput", "Average", "AWS/RDS", "DBInstanceIdentifier")
	case "AWS/RDS.WriteThroughput":
		getMetricsResp(startTime, endTime, periodCheck, "WriteThroughput", "Average", "AWS/RDS", "DBInstanceIdentifier")
	case "AWS/RDS.NetworkReceiveThroughput":
		getMetricsResp(startTime, endTime, periodCheck, "NetworkReceiveThroughput", "Average", "AWS/RDS", "DBInstanceIdentifier")
	case "AWS/RDS.NetworkTransmitThroughput":
		getMetricsResp(startTime, endTime, periodCheck, "NetworkTransmitThroughput", "Average", "AWS/RDS", "DBInstanceIdentifier")
	case "AWS/AutoScaling.GroupMinSize":
		getMetricsResp(startTime, endTime, periodCheck, "GroupMinSize", "Average", "AWS/AutoScaling", "AutoScalingGroupName")
	case "AWS/AutoScaling.GroupMaxSize":
		getMetricsResp(startTime, endTime, periodCheck, "GroupMaxSize", "Average", "AWS/AutoScaling", "AutoScalingGroupName")
	case "AWS/AutoScaling.GroupDesiredCapacity":
		getMetricsResp(startTime, endTime, periodCheck, "GroupDesiredCapacity", "Average", "AWS/AutoScaling", "AutoScalingGroupName")
	case "AWS/AutoScaling.GroupInServiceInstances":
		getMetricsResp(startTime, endTime, periodCheck, "GroupInServiceInstances", "Average", "AWS/AutoScaling", "AutoScalingGroupName")
	case "AWS/AutoScaling.GroupPendingInstances":
		getMetricsResp(startTime, endTime, periodCheck, "GroupPendingInstances", "Average", "AWS/AutoScaling", "AutoScalingGroupName")
	case "AWS/AutoScaling.GroupStandbyInstances":
		getMetricsResp(startTime, endTime, periodCheck, "GroupStandbyInstances", "Average", "AWS/AutoScaling", "AutoScalingGroupName")
	case "AWS/AutoScaling.GroupTerminatingInstances":
		getMetricsResp(startTime, endTime, periodCheck, "GroupTerminatingInstances", "Average", "AWS/AutoScaling", "AutoScalingGroupName")
	case "AWS/AutoScaling.GroupTotalInstances":
		getMetricsResp(startTime, endTime, periodCheck, "GroupTotalInstances", "Average", "AWS/AutoScaling", "AutoScalingGroupName")
	default:
		if opts.Statistics == "" || opts.NameSpace == "" || opts.DimensionName == "" {
			check.ExitCritical("Generic Mode requires all of the following -s statistics, -n name space and -d dimension name")
		}
		getMetricsResp(startTime, endTime, periodCheck, opts.Mode, opts.Statistics, opts.NameSpace, opts.DimensionName)
	}
}

// Set up the credentials for the session and make the call for the data parsed.
func getMetricsResp(startTime time.Time, endTime time.Time, periodCheck int, metricName string, statistics string, nameSpace string, dimensionName string) {
	if nameSpace == "AWS/EC2" {
		opts.SearchName = ec2SpecialCase()
		if opts.SearchName == "" {
			check.ExitUnknown("Error no instance ID was found for the Host Address given")
		}
	}

	if opts.SearchName == "" {
		check.ExitUnknown("Error a search name must be given")
	}

	// The data being requested
	params := &cloudwatch.GetMetricStatisticsInput{
		StartTime:  &startTime,
		EndTime:    aws.Time(endTime.UTC()),
		Period:     aws.Int64(int64(periodCheck)),
		MetricName: aws.String(metricName),
		Namespace:  aws.String(nameSpace),
		Dimensions: []*cloudwatch.Dimension{
			{
				Name:  aws.String(dimensionName),
				Value: aws.String(opts.SearchName),
			},
		},
		Statistics: []*string{
			aws.String(statistics),
		},
	}

	resp, err := svc.GetMetricStatistics(params)
	if err != nil {
		check.ExitCritical(err.Error())
	}
	addToPerf(resp, statistics, nameSpace)
}

// Gets the InstanceId if the instance public DNS address has been given. It will use the opts.SearchName if given.
func ec2SpecialCase() string {
	var returnId string

	if opts.SearchName == "" && opts.HostAddress == "" {
		check.ExitUnknown("One of the search metrics must be given -a HostAddress or -i Instance ID")
	}

	if opts.SearchName != "" && opts.HostAddress == "" {
		return opts.SearchName
	} else {
		ecc := ec2.New(sess)
		if ecc == nil {
			check.ExitUnknown("Unable to login to EC2")
		}

		resp, err := ecc.DescribeInstances(nil)
		if err != nil {
			check.ExitUnknown("Unable fetch list of EC2 Instances", err)
		}

		for _, reservation := range resp.Reservations {
			for _, instance := range reservation.Instances {
				if opts.SearchName != "" && (opts.SearchName == *instance.InstanceId) { // This sections is for when both SearchName(InstanceId) and HostAddress(PublicDnsName) have been given
					// Pedantic mode alerts if the PublicDnsName given is not the same as the one found with the InstanceId.
					if opts.Pedantic && (*instance.PublicDnsName != opts.HostAddress) {
						check.ExitWarning("Address specified does not match public DNS set for instance (address: %v vs DNS: %v)", opts.HostAddress, *instance.PublicDnsName)
					}
					returnId = opts.SearchName
				} else if opts.HostAddress == *instance.PublicDnsName {
					returnId = *instance.InstanceId
					if opts.DebugMode {
						fmt.Println("No EC2 instance found matching your Instance ID so looking up using the public DNS name")
					}

					if opts.Pedantic {
						check.ExitWarning("Instance ID specified does not match Instance ID set for the address specified (Instance given: %v)", opts.SearchName)
					}
				}
			}
		}
	}

	if returnId == "" {
		check.ExitUnknown("No EC2 instance found matching your Public DNS name and Instance ID")
	}

	return returnId
}

// Adds the value in correct type to the perf data
func addToPerf(resp *cloudwatch.GetMetricStatisticsOutput, stat string, nameSpace string) {
	var returnValue float64
	var UOM string

	if resp.Datapoints == nil {
		if opts.Mode == "AWS/EC2.CPUCreditUsage" || opts.Mode == "AWS/EC2.CPUCreditBalance" || opts.Mode == "AWS/RDS.CPUCreditUsage" || opts.Mode == "AWS/RDS.CPUCreditBalance" {
			check.ExitUnknown("No metric data found. The instance must be a T2 type to collect this metric")
		} else if nameSpace == "AWS/S3" {
			check.AddMetric(opts.Mode, 0, "")
			check.AddMessage("If you were not expecting a zero value you may have an incorrect timefame or you service is not monitored by cloudwatch")
			return
		} else {
			check.ExitUnknown("No metric data found, either the AWS is not set up to monitor this component or the timeframe doesn't contain a datapoint")
		}
	}

	switch stat {
	case "Average":
		returnValue = *resp.Datapoints[0].Average
	case "Minimum":
		returnValue = *resp.Datapoints[0].Minimum
	case "Maximum":
		returnValue = *resp.Datapoints[0].Maximum
	case "Sum":
		returnValue = *resp.Datapoints[0].Sum
	}

	switch *resp.Datapoints[0].Unit {
	case "Percent":
		UOM = "%"
	case "Bytes":
		UOM = "b"
	case "Milliseconds":
		UOM = "ms"
	case "Count":
		UOM = ""
	case "None":
		UOM = ""
	default:
		UOM = *resp.Datapoints[0].Unit
	}

	if opts.Mode == "AWS/EC2.StatusCheckFailed" || opts.Mode == "AWS/EC2.StatusCheckFailedAverageInstance" || opts.Mode == "AWS/EC2.StatusCheckFailedAverageSystem" {
		if returnValue == 0 {
			check.AddResult(plugin.OK, "Instance passed")
		} else if returnValue == 1 {
			check.AddResult(plugin.CRITICAL, "Instance failed")
		} else {
			value := strconv.Itoa(int(returnValue))
			check.ExitCritical("The metric type only supports 0(Passed) or 1(Failed), the system received " + value)
		}
	} else if opts.Mode == "AWS/Route53.HealthCheckStatus" {
		if returnValue == 1 {
			check.AddResult(plugin.OK, "Healthy")
		} else if returnValue == 0 {
			check.AddResult(plugin.CRITICAL, "Unhealthy")
		} else {
			value := strconv.Itoa(int(returnValue))
			check.ExitCritical("The metric type only supports 0(Passed) or 1(Failed), the system received " + value)
		}
	}
	check.AddMetric(opts.Mode, strconv.FormatFloat(returnValue, 'f', 3, 64), UOM, opts.Warning, opts.Critical)
}

// Validates all the arguments to prevent errors and warn users
func validateArgs(check *plugin.Plugin) {
	if (opts.AccessKey == "" || opts.SecretKey == "") && (opts.FilePath == "") { //If accessKey or secretKey not being used presume we should use session config file, either both accessKey and secretKey or the FilePath must be provided
		check.ExitUnknown("Either FilePath or AccessKey and SecretKey must be provided")
	}
	if ((opts.AccessKey != "") && (opts.SecretKey != "")) && (opts.FilePath != "") && (opts.DebugMode) {
		fmt.Println("AccessKey, SecretKey and FilePath provided, FilePath will be ignored")
	}
}

// Saving the last service check run time to file
func updateTimeState(newTime string) string {
	path := checkFilePath(check)

	file, err := os.OpenFile(path, syscall.O_RDWR|syscall.O_CREAT, 0660)
	if err != nil {
		check.ExitUnknown(err.Error())
	}

	defer file.Close()
	getLock(file, path)
	defer releaseLock(file)

	fileBytes, err := ioutil.ReadFile(path)
	if err != nil {
		check.ExitUnknown(err.Error())
	}

	file.Truncate(0)

	w := bufio.NewWriter(file)
	_, err = w.WriteString(newTime)
	if err != nil {
		check.ExitUnknown(err.Error())
	}

	w.Flush()

	return string(fileBytes)
}

// Set the flock on the file so no other processes can read or write to it
func getLock(file *os.File, path string) {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX)
	if err != nil {
		check.ExitUnknown("Error locking temporary file: " + path)
	}
}

// Release file lock
func releaseLock(file *os.File) {
	syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}

// Tests the locations of the path to check the file can be written
// Creates a file name using md5 to create a hash
func checkFilePath(check *plugin.Plugin) string {
	var hash string
	fileName := "AWS_Cloudwatch_"
	hash = opts.Mode + "," + opts.SearchName

	digest := make([]byte, len(hash))
	copy(digest[:], hash)
	hash = fmt.Sprintf("%x", md5.Sum(digest))
	fileName = fileName + string(hash[:]) + ".tmp"

	env := os.Getenv("OPSVIEW_BASE")

	path := env + "/tmp/" + fileName
	_, err := os.OpenFile(path, os.O_RDONLY, 0660)

	path = "/usr/local/nagios/tmp/" + fileName
	_, err1 := os.OpenFile(path, os.O_RDONLY, 0660)

	if !os.IsPermission(err) {
		path = env + "/tmp/" + fileName
	} else if !os.IsPermission(err1) {
		path = "/usr/local/nagios/tmp/" + fileName
	} else {
		path = "/tmp/" + fileName
		_, err = os.OpenFile(path, os.O_RDONLY, 0660)
		if os.IsPermission(err) {
			check.ExitUnknown("Error creating temp file unable to access " + path)
		}
	}
	return path
}

// Sets up the check and the help text
func checkPlugin() *plugin.Plugin {
	check := plugin.New("check_cloudwatch", "v1.0.0")
	check.Preamble = `Copyright (c) 2003-2017 Opsview Limited. All rights reserved.
This plugin tests the metrics of AWS CloudWatch.
`

	check.Description = `DESCRIPTION
Plugin supports following run modes:
Generic setup requires
-m Service check name
-s statistic (Average, Minimum, Maximum, Sum, SampleCount)
-n Name Space (AWS/EC2)
-d Dimension (example for EC2 = InstanceId)
-i Search Name (example for EC2's InstanceId = i-ad3e9b6d)

S3
AWS/S3.BucketSizeBytes: The amount of data in bytes stored in a bucket in the Standard storage class
AWS/S3.NumberOfObjects: The total number of objects stored in a bucket for all storage classes except for the GLACIER storage class
AWS/S3.AllRequests: The total number of HTTP requests made to a bucket
AWS/S3.GetRequests: The number of HTTP GET requests made for objects in a bucket
AWS/S3.PutRequests: The number of HTTP PUT requests made for objects in a bucket
AWS/S3.DeleteRequests: The number of HTTP DELETE requests made for objects in a bucket
AWS/S3.HeadRequests: The number of HTTP HEAD requests made to a bucket
AWS/S3.PostRequests: The number of HTTP POST requests made to a bucket
AWS/S3.ListRequests: The number of HTTP requests that list the contents of a bucket
AWS/S3.BytesDownloaded: The number bytes downloaded for requests made to a bucket, where the response includes a body
AWS/S3.BytesUploaded: The number bytes uploaded to a bucket that contain a request body
AWS/S3.4xxErrors: The number of HTTP 4xx client error status code requests made to a bucket
AWS/S3.5xxErrors: The number of HTTP 5xx client error status code requests made to a bucket
AWS/S3.FirstByteLatency: The per-request time from the complete request being received by a bucket to when the response starts to be returned
AWS/S3.TotalRequestLatency: The elapsed per-request time from the first byte received to the last byte sent to a bucket

ELB
AWS/ELB.BackendConnectionErrors: The number of connections that were not successfully established
AWS/ELB.HealthyHostCount: The number of healthy instances registered with your load balancer
AWS/ELB.HTTPCode_Backend: The number of HTTP response codes generated by registered instances
AWS/ELB.HTTPCode_ELB: The number of HTTP response codes of each code from the load balancer
AWS/ELB.Latency: The time elapsed, in seconds, after the request leaves the load balancer until the headers of the response are received
AWS/ELB.RequestCount: The number of requests completed or connections made during the specified interval
AWS/ELB.SpilloverCount: The total number of requests that were rejected because the surge queue is full
AWS/ELB.SurgeQueueLength: The total number of requests that are pending routing
AWS/ELB.UnHealthyHostCount: The number of unhealthy instances registered with your load balancer

Route53
AWS/Route53.ChildHealthCheckHealthyCount: The number health check that are healthy
AWS/Route53.ConnectionTime: The average time in milliseconds that a connection was established
AWS/Route53.HealthCheckPercentageHealthy: The percentage of healthy health checks
AWS/Route53.HealthCheckStatus: Health check status data is viewed across all regions
AWS/Route53.SSLHandshakeTime: The average time, in milliseconds, that it took health checkers to complete the SSL handshake.
AWS/Route53.TimeToFirstByte: The average time, in milliseconds, that it took health checkers to receive the first byte of the response to an HTTP or HTTPS request.

EC2
AWS/EC2.CPUCreditUsage: Must be T2 instance. The number of CPU credits consumed
AWS/EC2.CPUCreditBalance: Must be T2 instance. The number of CPU credits available
AWS/EC2.CPUUtilization: The percentage of allocated EC2 units that are in use
AWS/EC2.DiskReadOps: The number of completed read operations
AWS/EC2.DiskWriteOps: The number of completed write operations
AWS/EC2.DiskWriteBytes: Bytes written to all instance store volumes available to the instance
AWS/EC2.DiskReadBytes: Bytes read from all instance store volumes available to the instance
AWS/EC2.NetworkIn: The number of bytes received by the instance
AWS/EC2.NetworkOut: The number of bytes sent out on all network interfaces by the instance
AWS/EC2.NetworkPacketsIn: The number of packets received on all network interfaces by the instance
AWS/EC2.NetworkPacketsOut:The number of packets sent out on all network interfaces by the instance
AWS/EC2.StatusCheckFailed: Reports whether the instance has passed both the instance status check and the system status check

DynamoDB
AWS/DynamoDB.ConditionalCheckFailedRequests: The number of failed attempts to perform conditional writes
AWS/DynamoDB.ConsumedReadCapacityUnits: The number of read capacity units consumed over the specified time period
AWS/DynamoDB.ConsumedWriteCapacityUnits: The number of write capacity units consumed over the specified time period
AWS/DynamoDB.OnlineIndexConsumedWriteCapacity: The number of write capacity units consumed when adding a new global secondary index to a table
AWS/DynamoDB.OnlineIndexPercentageProgress: The percentage of completion when a new global secondary index is being added to a table
AWS/DynamoDB.OnlineIndexThrottleEvents: The number of write throttle events that occur when adding a new global secondary index to a table
AWS/DynamoDB.ProvisionedReadCapacityUnits: The number of provisioned read capacity units for a table or a global secondary index
AWS/DynamoDB.ProvisionedWriteCapacityUnits: The number of provisioned write capacity units for a table or a global secondary index
AWS/DynamoDB.ReadThrottleEvents: Requests to DynamoDB that exceed the provisioned read capacity units for a table or a global secondary index
AWS/DynamoDB.ReturnedBytes: The number of bytes returned by GetRecords operations (Amazon DynamoDB Streams) during the specified time period
AWS/DynamoDB.ReturnedItemCount: The number of items returned by Query or Scan operations during the specified time period
AWS/DynamoDB.ReturnedRecordsCount: The number of stream records returned by GetRecords operations (Amazon DynamoDB Streams) during the specified time period
AWS/DynamoDB.SuccessfulRequestLatency: Successful requests to DynamoDB or Amazon DynamoDB Streams during the specified time period
AWS/DynamoDB.SystemErrors: Requests to DynamoDB or Amazon DynamoDB Streams that generate an HTTP 500 status code during the specified time period
AWS/DynamoDB.ThrottledRequests: Requests to DynamoDB that exceed the provisioned throughput limits on a resource (such as a table or an index)
AWS/DynamoDB.UserErrors: Requests to DynamoDB or Amazon DynamoDB Streams that generate an HTTP 400 status code during the specified time period
AWS/DynamoDB.WriteThrottleEvents: Requests to DynamoDB that exceed the provisioned write capacity units for a table or a global secondary index

RDS
AWS/RDS.BinLogDiskUsage: The amount of disk space occupied by binary logs on the master
AWS/RDS.CPUUtilization: The percentage of CPU utilization
AWS/RDS.CPUCreditUsage: Must be T2 instance. The number of CPU credits consumed by the instance
AWS/RDS.CPUCreditBalance: Must be T2 instance. The number of CPU credits available for the instance to burst beyond its base CPU utilization
AWS/RDS.DatabaseConnections: The number of database connections in use
AWS/RDS.DiskQueueDepth: The number of outstanding IOs (read/write requests) waiting to access the disk
AWS/RDS.FreeableMemory: The amount of available random access memory
AWS/RDS.FreeStorageSpace: The amount of available storage space
AWS/RDS.ReplicaLag: The amount of time a Read Replica DB instance lags behind the source DB instance
AWS/RDS.SwapUsage: The amount of swap space used on the DB instance
AWS/RDS.ReadIOPS: The average number of disk I/O operations per second
AWS/RDS.WriteIOPS: The average number of disk I/O operations per second
AWS/RDS.ReadLatency: The average amount of time taken per disk I/O operation
AWS/RDS.WriteLatency: The average amount of time taken per disk I/O operation
AWS/RDS.ReadThroughput: The average number of bytes read from disk per second
AWS/RDS.WriteThroughput: The average number of bytes written to disk per second
AWS/RDS.NetworkReceiveThroughput: The incoming (Receive) network traffic on the DB instance, including both customer database traffic and Amazon RDS traffic used for monitoring and replication
AWS/RDS.NetworkTransmitThroughput: The outgoing (Transmit) network traffic on the DB instance, including both customer database traffic and Amazon RDS traffic used for monitoring and replication

AutoScaling
AWS/AutoScaling.GroupMinSize: The minimum size of the Auto Scaling group
AWS/AutoScaling.GroupMaxSize: The maximum size of the Auto Scaling group
AWS/AutoScaling.GroupDesiredCapacity: The number of instances that the Auto Scaling group attempts to maintain
AWS/AutoScaling.GroupInServiceInstances: The number of instances that are running as part of the Auto Scaling group. This metric does not include instances that are pending or terminating
AWS/AutoScaling.GroupPendingInstances: The number of instances that are pending. A pending instance is not yet in service. This metric does not include instances that are in service or terminating
AWS/AutoScaling.GroupStandbyInstances: The number of instances that are in a Standby state. Instances in this state are still running but are not actively in service
AWS/AutoScaling.GroupTerminatingInstances: The number of instances that are in the process of terminating. This metric does not include instances that are in service or pending
AWS/AutoScaling.GroupTotalInstances: The total number of instances in the Auto Scaling group. This metric identifies the number of instances that are in service, pending, and terminating
`
	return check
}
