#!/usr/bin/python

import argparse
import logging
import time
import boto3
import pprint
import socket
from botocore.exceptions import ClientError
from sys import exit
from datetime import tzinfo, timedelta, datetime
from os.path import basename

parser = argparse.ArgumentParser(description="This is a quick and dirty tool to build public 'Classic' ec2 instances.")
parser.add_argument('--ami', help='AMI to Use, defaults to amazon linux ami-f2d3638a in us-west-2',default='ami-f2d3638a')
parser.add_argument('--instance-type', help='AWS Instance Type', default='t2.micro')
parser.add_argument('--region', help='aws region to use', default='us-west-2')
parser.add_argument('--subnet-id', help='Which sunbet to use',default='')
parser.add_argument('--count', help='How many instances to make',default=1)
parser.add_argument('--hostname', help='Hostname for this machine',required = True)
parser.add_argument('--profile', help='AWS profile to use', default="default")
parser.add_argument('--open-ports', help='Create new AWS security group with these open ports',default=[22,80,443,8080])
parser.add_argument('--debug', help='Enable debug mode.', action="store_true")
args = parser.parse_args()

if args.debug:
    logging.basicConfig(level = logging.DEBUG, format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
    logger = logging.getLogger(__name__)

def main(args):
    global logger
    if None == args.hostname:
        print "Error: Missing --hostname\n\n"
        parser.print_help()
        exit(1)
    aws = AWSElassticCompute(args)
    aws.launchEC2()

class AWSElassticCompute:

    key_pair = False
    security_group_id = False
    disk_size = 8

    def __init__(self,args):
        a = {}
        a['profile_name'] = args.profile
        if args.region:
          a['region_name'] = args.region
        boto3.setup_default_session(**a)
        self.session = boto3.Session(**a)
        self.args = args
        self.pp = pprint.PrettyPrinter(indent=4)
        self.account_id = self.session.client('sts').get_caller_identity().get('Account')
        self.ec2 = boto3.client('ec2')
        self.res_ec2 = self.session.resource('ec2')
        self.log = logging.getLogger(__name__)
        self.log.debug("ARGS: %s" % (self.pp.pformat(args)))


    def checkServerSSH(self, address ):
        # Create a TCP socket
        s = socket.socket()
        try:
            s.connect((address, 22))
            self.log.info("Host is up and SSH is ready")
            return True
        except socket.error, e:
            return False

    def makeKeyPair(self):
        """
        Generate a new keypair and use it to create our instance
        """
        today = datetime.now()
        name = "%s-%s"%(self.args.hostname,today.strftime("%Y-%m-%d_%H-%M-%S"))
        res = self.ec2.create_key_pair(KeyName=name,DryRun=False)
        self.log.debug('Create new keypair:',res)
        self.log.debug(res)
        kp = open("%s.pem,"%(res['KeyName']),'w')
        kp.write(res['KeyMaterial'])
        kp.close
        self.key_pair = res['KeyName']
        return self.key_pair



    def makeSecurityGroup(self):
        """
        Make a generic security group
        """

        try:
            today = datetime.now()
            name = "%s-%s"%(self.args.hostname,today.strftime("%Y-%m-%d_%H-%M-%S"))
            response = self.ec2.create_security_group(
                Description="Auto Generated SecurityGroup '%s'"%(self.args.hostname),
                GroupName="%s-sg"%(name),
                DryRun=False
            )
            security_group_id = response['GroupId']
            print('Security Group Created %s.' % (security_group_id))
            rules = []
            for port in self.args.open_ports:
                rules.append({
                    'IpProtocol': 'tcp',
                    'FromPort': port,
                    'ToPort': port,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                })
            data = self.ec2.authorize_security_group_ingress(GroupId=security_group_id, IpPermissions=rules)
            self.log.info('Ingress Successfully Set %s' % data)
            self.security_group_id = security_group_id
        except ClientError as e:
            self.log.error(e)

        return self.security_group_id

    def makeAnsibleFiles(self,ip):
      s = open('.host','w')
      s.write("[webservers]\n# Add hosts here\n%s\n\n\n[webservers:vars]\n# Local variables for Ansible playbooks\nansible_user=ubuntu\ngithub_user=analogrithems\napp_name=reactiveops_coder_test\n"%(ip))
      s.close()
      print("Run: ansible-playbook deploy.yml --key-file %s.pem"%(self.key_pair))
    def launchEC2(self):
        if not self.key_pair:
            kp = self.makeKeyPair()
        if not self.security_group_id:
            sg = self.makeSecurityGroup()
        try:
          res = self.ec2.run_instances(
              ImageId=self.args.ami,
              KeyName=self.key_pair,
              InstanceType=self.args.instance_type,
              MinCount=self.args.count,
              MaxCount=self.args.count,
              SecurityGroupIds=[self.security_group_id],
              BlockDeviceMappings=[{
                  "DeviceName": "/dev/sda1",
                  "Ebs": {
                      "VolumeType": "gp2",
                      "VolumeSize": self.disk_size,
                      "DeleteOnTermination": True
                  },
              }],
              TagSpecifications=[
                  {
                      'ResourceType': 'instance',
                      'Tags': [
                          {
                              'Key': 'Name',
                              'Value': self.args.hostname
                          },
                      ]
                  },
              ]
          )
        except:
            vpc_response = self.ec2.create_default_vpc(DryRun=False)
            logger.debug(vpc_response)
            res = self.ec2.run_instances(
                ImageId=self.args.ami,
                KeyName=self.key_pair,
                InstanceType=self.args.instance_type,
                MinCount=self.args.count,
                MaxCount=self.args.count,
                SecurityGroupIds=[self.security_group_id],
                BlockDeviceMappings=[{
                    "DeviceName": "/dev/sda1",
                    "Ebs": {
                        "VolumeType": "gp2",
                        "VolumeSize": self.disk_size,
                        "DeleteOnTermination": True
                    },
                }],
                NetworkInterfaces=[{
                    "DeviceIndex": 0,
                    "AssociatePublicIpAddress": True
                }],
                TagSpecifications=[
                    {
                        'ResourceType': 'instance',
                        'Tags': [
                            {
                                'Key': 'name',
                                'Value': self.args.hostname
                            },
                        ]
                    },
                ]
            )
        self.log.debug("Create EC2 host: %s"%(res))
        instance_id = res['Instances'][0]['InstanceId']
        waiting = True
        while waiting:
            try:
                instance = self.res_ec2.Instance(instance_id)
                if instance.state['Name'] == 'terminated':
                    sendError( '[%s] Instance was terminated prior to successful initialization' % self.args.hostname )

                logging.info( '[%s] Waiting for instance to become available, currently %s' % ( self.args.hostname, instance.state['Name'] ) )
                if instance.state['Name'] == 'running':
                    logger.info(instance)
                    waiting = False
                else:
                    time.sleep(30)
            except ClientError as e:
                time.sleep(30)
        sshready = self.checkServerSSH( instance.public_ip_address )
        while sshready != True:
            logging.info( '[%s] Waiting for SSH to respond, currently %s' % ( instance.public_ip_address, sshready ) )
            time.sleep(30)
            sshready = self.checkServerSSH( instance.public_ip_address )
        self.log.debug("Creates EC2 host: %s"%(instance))
        self.makeAnsibleFiles(instance.public_ip_address)



if __name__ == '__main__':
  main(args)