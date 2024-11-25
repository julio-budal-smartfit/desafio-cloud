# Provider configuration
provider "aws" {
  region = "us-east-1"
}

resource "aws_vpc" "cloudwise_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "cloudwise-vpc"
  }
}

resource "aws_internet_gateway" "cloudwise_igw" {
  vpc_id = aws_vpc.cloudwise_vpc.id

  tags = {
    Name = "cloudwise-igw"
  }
}

# Elastic IP para o NAT Gateway
resource "aws_eip" "nat" {
  domain = "vpc"
  
  tags = {
    Name = "cloudwise-nat-eip"
  }
}

# NAT Gateway
resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_subnet_1.id

  tags = {
    Name = "cloudwise-nat"
  }

  depends_on = [aws_internet_gateway.cloudwise_igw]
}

# Route Table para subnets privadas
resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.cloudwise_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = {
    Name = "cloudwise-private-rt"
  }
}

# Route Table Associations para subnets privadas
resource "aws_route_table_association" "private_1" {
  subnet_id      = aws_subnet.private_subnet_1.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "private_2" {
  subnet_id      = aws_subnet.private_subnet_2.id
  route_table_id = aws_route_table.private_rt.id
}

# Public Subnets
resource "aws_subnet" "public_subnet_1" {
  vpc_id            = aws_vpc.cloudwise_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"

  map_public_ip_on_launch = true

  tags = {
    Name = "cloudwise-public-1"
  }
}

resource "aws_subnet" "public_subnet_2" {
  vpc_id            = aws_vpc.cloudwise_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"

  map_public_ip_on_launch = true

  tags = {
    Name = "cloudwise-public-2"
  }
}

# Private Subnets
resource "aws_subnet" "private_subnet_1" {
  vpc_id            = aws_vpc.cloudwise_vpc.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "cloudwise-private-1"
  }
}

resource "aws_subnet" "private_subnet_2" {
  vpc_id            = aws_vpc.cloudwise_vpc.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "cloudwise-private-2"
  }
}

# Route Tables
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.cloudwise_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.cloudwise_igw.id
  }

  tags = {
    Name = "cloudwise-public-rt"
  }
}

# Route Table Associations
resource "aws_route_table_association" "public_1" {
  subnet_id      = aws_subnet.public_subnet_1.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "public_2" {
  subnet_id      = aws_subnet.public_subnet_2.id
  route_table_id = aws_route_table.public_rt.id
}

#####################################
# Security Groups
#####################################

resource "aws_security_group" "alb_sg" {
  name        = "cloudwise-alb-sg"
  description = "ALB Security Group"
  vpc_id      = aws_vpc.cloudwise_vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "cloudwise-alb-sg"
  }
}

resource "aws_security_group" "ecs_sg" {
  name        = "cloudwise-ecs-sg"
  description = "ECS Security Group"
  vpc_id      = aws_vpc.cloudwise_vpc.id

  ingress {
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "cloudwise-ecs-sg"
  }
}

resource "aws_security_group" "rds_sg" {
  name        = "cloudwise-rds-sg"
  description = "RDS Security Group"
  vpc_id      = aws_vpc.cloudwise_vpc.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "cloudwise-rds-sg"
  }
}

#####################################
# RDS Configuration
#####################################

resource "aws_db_subnet_group" "rds_subnet_group" {
  name       = "cloudwise-rds-subnet-group"
  subnet_ids = [aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id]

  tags = {
    Name = "cloudwise-rds-subnet-group"
  }
}

resource "aws_db_instance" "cloudwise_db" {
  identifier           = "cloudwise-db"
  engine              = "postgres"
  engine_version      = "15.10"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  storage_type        = "gp2"
  db_name             = "cloudwise_production"
  username            = "cloudwise"
  password            = "your_secure_password" # Use variables in production

  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.rds_subnet_group.name

  multi_az               = false
  publicly_accessible    = false
  skip_final_snapshot    = true

  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "Mon:04:00-Mon:05:00"

  tags = {
    Name = "cloudwise-db"
  }
}

#####################################
# IAM Roles and Policies
#####################################

# ECS Task Execution Role
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "cloudwise-ecs-task-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

# Anexar a política AmazonECSTaskExecutionRolePolicy
resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Adicionar política específica para CloudWatch Logs
resource "aws_iam_role_policy" "ecs_task_execution_role_cloudwatch" {
  name = "cloudwise-ecs-task-execution-cloudwatch"
  role = aws_iam_role.ecs_task_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

# ECS Task Role
resource "aws_iam_role" "ecs_task_role" {
  name = "cloudwise-ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_secretsmanager_secret" "rails_secret" {
  name = "cloudwise/rails/secret_key_base"
  
  tags = {
    Name = "cloudwise-rails-secret"
  }
}

resource "aws_secretsmanager_secret_version" "rails_secret" {
  secret_id     = aws_secretsmanager_secret.rails_secret.id
  secret_string = "bb753829112a75548ba6ae04e62fea89"  # Use a chave fornecida ou gere uma nova
}

# Política para o Task Role
resource "aws_iam_role_policy" "ecs_task_role_policy" {
  name = "cloudwise-ecs-task-role-policy"
  role = aws_iam_role.ecs_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "ecs_task_secrets" {
  name = "cloudwise-ecs-secrets-policy"
  role = aws_iam_role.ecs_task_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [aws_secretsmanager_secret.rails_secret.arn]
      }
    ]
  })
}

#####################################
# CloudWatch Logs
#####################################

resource "aws_cloudwatch_log_group" "cloudwise_logs" {
  name              = "/ecs/cloudwise-app"
  retention_in_days = 30

  tags = {
    Name = "cloudwise-logs"
  }
}

#####################################
# ECR Repository
#####################################

resource "aws_ecr_repository" "cloudwise_repo" {
  name = "cloudwise-app"

  tags = {
    Name = "cloudwise-ecr"
  }
}

#####################################
# ECS Cluster and Services
#####################################

resource "aws_ecs_cluster" "cloudwise_cluster" {
  name = "cloudwise-cluster"

  tags = {
    Name = "cloudwise-cluster"
  }
}

resource "aws_lb_target_group" "cloudwise_tg" {
  name        = "cloudwise-tg"
  port        = 3000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.cloudwise_vpc.id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 120
    matcher            = "200-399"
    path               = "/up"  # Endpoint específico para health check
    port               = "traffic-port"
    protocol           = "HTTP"
    timeout            = 30
    unhealthy_threshold = 5
  }

  # Aumentar o tempo de draining para permitir requests em andamento finalizarem
  deregistration_delay = 120

  tags = {
    Name = "cloudwise-target-group"
  }
}

resource "aws_ecs_task_definition" "cloudwise_task" {
  family                   = "cloudwise-app"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 512  # Aumentado para 512
  memory                   = 1024 # Aumentado para 1GB
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn           = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name      = "cloudwise-app"
      image     = "${aws_ecr_repository.cloudwise_repo.repository_url}:latest"
      essential = true
      portMappings = [
        {
          containerPort = 3000
          hostPort      = 3000
          protocol      = "tcp"
        }
      ]
      environment = [
        {
          name  = "RAILS_ENV"
          value = "production"
        },
        {
          name  = "DATABASE_URL"
          value = "postgresql://${aws_db_instance.cloudwise_db.username}:${aws_db_instance.cloudwise_db.password}@${aws_db_instance.cloudwise_db.endpoint}/${aws_db_instance.cloudwise_db.db_name}"
        },
        {
          name  = "RAILS_SERVE_STATIC_FILES"
          value = "true"
        },
        {
          name  = "RAILS_LOG_TO_STDOUT"
          value = "true"
        },
        {
          name  = "RAILS_MAX_THREADS"
          value = "5"
        },
        {
          name  = "WEB_CONCURRENCY"
          value = "2"
        },
        {
          name  = "PORT"
          value = "3000"
        },
        {
          name  = "BINDING"
          value = "0.0.0.0"
        }
      ]
      secrets = [
        {
          name      = "SECRET_KEY_BASE"
          valueFrom = aws_secretsmanager_secret.rails_secret.arn
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.cloudwise_logs.name
          awslogs-region        = "us-east-1"
          awslogs-stream-prefix = "ecs"
        }
      }
      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:3000/up || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 120  # 2 minutos para inicialização
      }
      startTimeout = 120  # 2 minutos para iniciar
      stopTimeout  = 120  # 2 minutos para parar gracefully
    }
  ])

  tags = {
    Name = "cloudwise-task"
  }
}

#####################################
# Application Load Balancer
#####################################

resource "aws_lb" "cloudwise_alb" {
  name               = "cloudwise-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.public_subnet_1.id, aws_subnet.public_subnet_2.id]

  tags = {
    Name = "cloudwise-alb"
  }
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = aws_lb.cloudwise_alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.cloudwise_tg.arn
  }
}

resource "aws_lb_listener" "front_end_https" {
  load_balancer_arn = aws_lb.cloudwise_alb.arn
  port              = "443"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.cloudwise_tg.arn
  }
}

resource "aws_ecs_service" "cloudwise_service" {
  name            = "cloudwise-service"
  cluster         = aws_ecs_cluster.cloudwise_cluster.id
  task_definition = aws_ecs_task_definition.cloudwise_task.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id]
    security_groups  = [aws_security_group.ecs_sg.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.cloudwise_tg.arn
    container_name   = "cloudwise-app"
    container_port   = 3000
  }

  depends_on = [aws_lb_listener.front_end, aws_lb_listener.front_end_https]

  tags = {
    Name = "cloudwise-service"
  }
}
