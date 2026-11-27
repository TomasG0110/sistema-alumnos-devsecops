// Jenkinsfile - Pipeline DevSecOps de "Sistema Alumnos" (SecureDev · OCY1102)
pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 40, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    triggers {
        pollSCM('H/3 * * * *')
    }

    environment {
        PIP_DISABLE_PIP_VERSION_CHECK = '1'
    }

    stages {
        stage('Build') {
            steps {
                script {
                    def sha = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
                    env.APP_VERSION = "1.0.${env.BUILD_NUMBER}+${sha}"
                }
                echo "Versión de este build: ${env.APP_VERSION}"
                sh 'git log -1 --format="Commit %h de %an: %s"'
                sh 'rm -rf .venv reports && mkdir -p reports'
                sh 'python3 -m venv .venv'
                sh '.venv/bin/pip install --quiet -r requirements.txt -r requirements-dev.txt'
                sh '.venv/bin/python -m compileall -q app.py'
            }
        }

        stage('Test') {
            steps {
                sh '.venv/bin/python -m pytest --junitxml=reports/junit.xml'
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'reports/junit.xml'
                }
            }
        }

        stage('Security Review (SAST)') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    sh '''
                        bandit -r app.py -f json -o reports/bandit.json || true
                        bandit -r app.py -f txt -o reports/bandit.txt
                    '''
                }
            }
        }

        stage('Dependency Management (SCA)') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    sh '''
                        pip-audit -r requirements.txt -f json -o reports/pip-audit.json || true
                        pip-audit -r requirements.txt > reports/pip-audit.txt
                    '''
                }
            }
        }

        stage('Deploy Staging') {
            steps {
                sh 'bash scripts/deploy.sh staging 5001'
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    sh 'python3 scripts/zap_scan.py http://jenkins:5001'
                }
            }
        }

        stage('Deploy Producción') {
            when {
                expression { currentBuild.currentResult == 'SUCCESS' }
            }
            steps {
                sh 'bash scripts/deploy.sh produccion 5000'
                script { env.PRODUCCION = env.APP_VERSION }
            }
        }
    }

    post {
        always {
            withEnv(["RESULTADO=${currentBuild.currentResult}"]) {
                sh 'python3 scripts/trazabilidad.py'
            }
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
    }
}