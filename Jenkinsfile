pipeline {
    agent any
    // {
    //     label "BuildAgent2"
    // }
    // environment {
    //     registry = "756519817970.dkr.ecr.us-east-2.amazonaws.com/postboard-server-repo"
    // }
    stages {
        stage("Checkout") {
            steps {
                checkout scm
            }
        }
        
        // stage("Code Coverage") {
        //     steps {
        //         jacoco()
        //     }
        // }
       
       
        stage("Build & Upload") {
            steps {
                sh "npm install"
        
            }
        }




        stage ("Code Quality") {
            steps {
                withSonarQubeEnv("SonarQube") {
                    sh "npm install sonar-scanner"
                    sh "npm run sonar"
                }
            }
        }   


stage('Build and Push Docker Image') {
    steps {
        script {
            sh 'aws ecr get-login-password --region us-east-2 | docker login --username AWS --password-stdin 577638372446.dkr.ecr.us-east-2.amazonaws.com'

            def buildTag = "build-${env.BUILD_NUMBER}"
            def latestTag = "build-${env.BUILD_NUMBER}-latest" // Dynamic 'latest' tag
            
            // Build the image with the Jenkins build number tag
            sh "docker build --no-cache -t 577638372446.dkr.ecr.us-east-2.amazonaws.com/docker-images:${buildTag} ."
            
            // Tag the image with the dynamic 'latest' tag (not overwriting 'latest')
            sh "docker tag 577638372446.dkr.ecr.us-east-2.amazonaws.com/docker-images:${buildTag} 577638372446.dkr.ecr.us-east-2.amazonaws.com/docker-images:${latestTag}"

            // Push both tags to ECR
            sh "docker push 577638372446.dkr.ecr.us-east-2.amazonaws.com/docker-images:${buildTag}"
            sh "docker push 577638372446.dkr.ecr.us-east-2.amazonaws.com/docker-images:${latestTag}"
        }
    }
}



stage('Deploy Application') {
    steps {
        script {
            // Trigger the deployment script on the target server
            sshagent(['4867e2a4-980d-4950-ba51-c4ca1f763678']) {
                sh '''#!/bin/bash
                ssh -o StrictHostKeyChecking=no ec2-user@18.119.103.195 "
                cd /home/ec2-user/main/scripts
                chmod +x pull_and_deploy-nodeserver.sh
                ./pull_and_deploy-nodeserver.sh"
                '''
            }
        }
    }
}
 



        
        //     stage ("terraform init") {
        //     steps {
        //         sh ("terraform init -reconfigure") 
        //     }
        // }
        
        // stage ("terraform plan") {
        //     steps {
        //         sh ('terraform plan') 
        //     }
        // }

        // stage ("terraform apply") {
        //     steps {
        //         echo "Terraform action is --> ${action}"
        //         sh ('terraform ${action} --auto-approve') 
        //   }
        // }
        
        
//         stage ('DEV Notify')  {
//             steps {

//       slackSend(channel:'jenkins-server', message: "Job is successful, here is the info -  Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]' (${env.BUILD_URL})")
//   }
// }


//  stage ('DEV Approve')  {
//             steps {
//                echo "Taking approval from DEV Manager for QA Deployment"     
//             timeout(time: 7, unit: 'DAYS') {
//             input message: 'Do you approve QA Deployment?', submitter: 'admin'
//             }

// }
//    }




        
    }
}
