variable "cluster-name" {
  default = "terraform-eks-demo"
  type    = string
}


provider "aws" {
  access_key = ""
  secret_key = ""
  region     = ""
}


provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.cluster.token
  load_config_file       = false
  version                = "~> 1.10"
}

data "aws_eks_cluster" "cluster" {
  name = aws_eks_cluster.demo.id
}

data "aws_eks_cluster_auth" "cluster" {
  name = aws_eks_cluster.demo.id
}

data "aws_caller_identity" "current" {}
// VPC

# This data source is included for ease of sample architecture deployment
# and can be swapped out as necessary.
data "aws_availability_zones" "available" {}

resource "aws_vpc" "demo" {
  cidr_block = "10.0.0.0/16"

  tags = "${
    map(
      "Name", "terraform-eks-demo-node",
      "kubernetes.io/cluster/${var.cluster-name}", "shared",
    )
  }"
}

resource "aws_subnet" "demo" {
  count = 2

  availability_zone = "${data.aws_availability_zones.available.names[count.index]}"
  cidr_block        = "10.0.${count.index}.0/24"
  vpc_id            = "${aws_vpc.demo.id}"

  tags = {
    "kubernetes.io/cluster/${var.cluster-name}" = "shared",
    "kubernetes.io/role/elb" = "1"
  }
}

resource "aws_internet_gateway" "demo" {
  vpc_id = "${aws_vpc.demo.id}"

  
}

resource "aws_route_table" "demo" {
  vpc_id = "${aws_vpc.demo.id}"

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.demo.id}"
  }
}

resource "aws_route_table_association" "demo" {
  count = 2

  subnet_id      = "${aws_subnet.demo.*.id[count.index]}"
  route_table_id = "${aws_route_table.demo.id}"
}

resource "aws_iam_policy" "alb_policy" {
  name        = "alb-policy"
  description = "An alb policy"
  path = "/"
  policy = "${file("iam-policy.json")}"
}

//EKS Master

resource "aws_iam_role" "demo-cluster" {
  name = "terraform-eks-demo-cluster"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

//Mesh policy

resource "aws_iam_policy" "mesh_policy" {
  name        = "mesh-policy"
  description = "A mesh policy"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["appmesh:*"],
      "Resource": "*"
    }
  ]
}
EOF
}



resource "aws_iam_policy" "policy_cloudwatch" {
  name        = "policy_cloudwatch"
  description = "This policy allow EKS workers to send logs into cloudwatch"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogStream",
        "logs:CreateLogGroup",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:PutLogEvents"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF

}

resource "aws_iam_role_policy_attachment" "demo-cluster-AmazonCloudWatchPolicy" {
  policy_arn = "${aws_iam_policy.policy_cloudwatch.arn}"
  role       = "${aws_iam_role.demo-cluster.name}"
}

resource "aws_iam_role_policy_attachment" "demo-cluster-AmazonEKSALBPolicy" {
  policy_arn = "${aws_iam_policy.alb_policy.arn}"
  role       = "${aws_iam_role.demo-cluster.name}"
}

resource "aws_iam_role_policy_attachment" "demo-cluster-AmazonEKSMeshPolicy" {
  policy_arn = "${aws_iam_policy.mesh_policy.arn}"
  role       = "${aws_iam_role.demo-cluster.name}"
}

resource "aws_iam_role_policy_attachment" "demo-cluster-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = "${aws_iam_role.demo-cluster.name}"
}

resource "aws_iam_role_policy_attachment" "demo-cluster-AmazonEKSServicePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
  role       = "${aws_iam_role.demo-cluster.name}"
}

//EKS Master Security Groups

resource "aws_security_group" "demo-cluster" {
  name        = "terraform-eks-demo-cluster"
  description = "Cluster communication with worker nodes"
  vpc_id      = "${aws_vpc.demo.id}"


  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  
}

// Key
resource "aws_kms_key" "eks" {
  description = "EKS Secret Encryption Key"
}


//EKS Master Cluster

resource "aws_eks_cluster" "demo" {
  name     = "${var.cluster-name}"
  role_arn = "${aws_iam_role.demo-cluster.arn}"
  version = "1.15"

  vpc_config {
    security_group_ids = ["${aws_security_group.demo-cluster.id}"]
    subnet_ids         = flatten(["${aws_subnet.demo.*.id}"])
  }

  encryption_config {
      provider   { key_arn = aws_kms_key.eks.arn }
      resources        = ["secrets"]
  }
 
 timeouts {
    create = "20m"
    delete = "20m"
  }


  depends_on = [
    "aws_iam_role_policy_attachment.demo-cluster-AmazonEKSClusterPolicy",
    "aws_iam_role_policy_attachment.demo-cluster-AmazonEKSServicePolicy",
     "aws_iam_role_policy_attachment.demo-cluster-AmazonEKSMeshPolicy"
  ]
}

/*

locals {
  kubeconfig = <<KUBECONFIG


apiVersion: v1
clusters:
- cluster:
    server: ${aws_eks_cluster.demo.endpoint}
    certificate-authority-data: ${aws_eks_cluster.demo.certificate_authority.0.data}
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: aws
  name: aws
current-context: aws
kind: Config
preferences: {}
users:
- name: aws
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1alpha1
      command: aws-iam-authenticator
      args:
        - "token"
        - "-i"
        - "${var.cluster-name}"
KUBECONFIG
}

output "kubeconfig" {
  value = "${local.kubeconfig}"
}
*/
//worker nodes

resource "aws_iam_role" "demo-node" {
  name = "terraform-eks-demo-node"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}






resource "aws_iam_role_policy_attachment" "demo-node-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = "${aws_iam_role.demo-node.name}"
}

resource "aws_iam_role_policy_attachment" "demo-node-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = "${aws_iam_role.demo-node.name}"
}

resource "aws_iam_role_policy_attachment" "demo-node-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = "${aws_iam_role.demo-node.name}"
}

resource "aws_iam_role_policy_attachment" "demo-node-AWSAppMeshFullAccess" {
  policy_arn = "arn:aws:iam::aws:policy/AWSAppMeshFullAccess"
  role       = "${aws_iam_role.demo-node.name}"
}

resource "aws_iam_role_policy_attachment" "demo-node-AWSXRayDaemonWriteAccess" {
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
  role       = "${aws_iam_role.demo-node.name}"
}


resource "aws_iam_role_policy_attachment" "demo-node-AmazonCloudWatchPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
  role       = "${aws_iam_role.demo-node.name}"
}



resource "aws_iam_instance_profile" "demo-node" {
  name = "terraform-eks-demo"
  role = "${aws_iam_role.demo-node.name}"
}

// Worker Node Security Group

resource "aws_security_group" "demo-node" {
  name        = "terraform-eks-demo-node"
  description = "Security group for all nodes in the cluster"
  vpc_id      = "${aws_vpc.demo.id}"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }


  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = "${
    map(
      "Name", "terraform-eks-demo-node",
      "kubernetes.io/cluster/${var.cluster-name}", "owned",
    )
  }"
}

resource "aws_security_group_rule" "demo-node-ingress-self" {
  description              = "Allow node to communicate with each other"
  from_port                = 0
  protocol                 = "-1"
  security_group_id        = "${aws_security_group.demo-node.id}"
  source_security_group_id = "${aws_security_group.demo-node.id}"
  to_port                  = 65535
  type                     = "ingress"
}

resource "aws_security_group_rule" "demo-node-ingress-cluster" {
  description              = "Allow worker Kubelets and pods to receive communication from the cluster control plane"
  from_port                = 1025
  protocol                 = "tcp"
  security_group_id        = "${aws_security_group.demo-node.id}"
  source_security_group_id = "${aws_security_group.demo-cluster.id}"
  to_port                  = 65535
  type                     = "ingress"
}

//Worker Node Access to EKS Master Cluster

resource "aws_security_group_rule" "demo-cluster-ingress-node-https" {
  description              = "Allow pods to communicate with the cluster API Server"
  from_port                = 443
  protocol                 = "tcp"
  security_group_id        = "${aws_security_group.demo-cluster.id}"
  source_security_group_id = "${aws_security_group.demo-node.id}"
  to_port                  = 443
  type                     = "ingress"
}

// ALB Service Account IAM

provider "external" {
  version = "~> 1.2"
}


resource "aws_iam_openid_connect_provider" "main" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.external.thumbprint.result.thumbprint]
  url             = data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer
}

data "external" "thumbprint" {
  program =    ["sh","${path.module}/oidc_thumbprint.sh", "us-east-1"]
  depends_on = [aws_eks_cluster.demo]
}

resource "aws_iam_role" "eks_alb_ingress_controller" {
  name        = "eks-alb-ingress-controller"
  description = "Permissions required by the Kubernetes AWS ALB Ingress controller to do it's job."

  force_detach_policies = true
c
  assume_role_policy = <<ROLE
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${replace(data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer, "https://", "")}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${replace(data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer, "https://", "")}:sub": "system:serviceaccount:kube-system:alb-ingress-controller"
        }
      }
    }
  ]
}
ROLE
}



resource "aws_iam_role_policy_attachment" "alb_policy" {
  policy_arn = aws_iam_policy.alb_policy.arn
  role       = aws_iam_role.eks_alb_ingress_controller.name
}


resource "kubernetes_cluster_role" "ingress" {
  metadata {
    name = "alb-ingress-controller"
    labels = {
      "app.kubernetes.io/name"       = "alb-ingress-controller"
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }

  rule {
    api_groups = ["", "extensions"]
    resources  = ["configmaps", "endpoints", "events", "ingresses", "ingresses/status", "services"]
    verbs      = ["create", "get", "list", "update", "watch", "patch"]
  }

  rule {
    api_groups = ["", "extensions"]
    resources  = ["nodes", "pods", "secrets", "services", "namespaces"]
    verbs      = ["get", "list", "watch"]
  }
}

resource "kubernetes_cluster_role_binding" "ingress" {
  metadata {
    name = "alb-ingress-controller"
    labels = {
      "app.kubernetes.io/name"       = "alb-ingress-controller"
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.ingress.metadata[0].name
  }
  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.ingress.metadata[0].name
    namespace = kubernetes_service_account.ingress.metadata[0].namespace
  }

  depends_on = [kubernetes_cluster_role.ingress]
}

resource "kubernetes_service_account" "ingress" {
  automount_service_account_token = true
  metadata {
    name      = "alb-ingress-controller"
    namespace = "kube-system"
    labels    = {
      "app.kubernetes.io/name"       = "alb-ingress-controller"
      "app.kubernetes.io/managed-by" = "terraform"
    }
    timeouts {
      create = "20m"
      delete = "20m"
    }
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.eks_alb_ingress_controller.arn
    }
  }
}

/*

resource "aws_iam_role" "alb_role" {
  assume_role_policy = "${file("iam-policy.json")}"
  name               = "alb-policy"
  path = "/"
}
*/





resource "aws_eks_node_group" "demo-node-group" {
  cluster_name    = "${var.cluster-name}"
  node_group_name = "demo-node-group"
  node_role_arn   = "${aws_iam_role.demo-node.arn}"
  subnet_ids      = flatten(["${aws_subnet.demo.*.id}"])

  scaling_config {
    desired_size = 2
    max_size     = 2
    min_size     = 2
  }
  instance_types =   ["t2.medium"]
  
  timeouts {
    create = "20m"
    delete = "20m"
  }
  remote_access {
    ec2_ssh_key = "test_key_pair"
    source_security_group_ids = ["${aws_security_group.demo-node.id}"]

  }

  tags = {
    Environment = "test"
  }


  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.demo-node-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.demo-node-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.demo-node-AmazonEC2ContainerRegistryReadOnly,
    aws_iam_role_policy_attachment.demo-node-AWSAppMeshFullAccess,
    aws_iam_role_policy_attachment.demo-node-AWSXRayDaemonWriteAccess
    
  ]
  
  /*provisioner "local-exec" {
    command = "kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/aws-alb-ingress-controller/v1.1.5/docs/examples/rbac-role.yaml"
  }

  provisioner "local-exec" {
    command = "curl -sS \"https://raw.githubusercontent.com/kubernetes-sigs/aws-alb-ingress-controller/v1.1.5/docs/examples/alb-ingress-controller.yaml\" | sed \"s/# - --cluster-name=devCluster/- --cluster-name=${var.cluster-name}/g\" | kubectl apply -f -"
  }*/

}


resource "aws_ecr_repository" "terraform-eks-demo-ecr" {
  name = "terraform-eks-demo-ecr"
}


