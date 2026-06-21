pipeline {
    agent any

    environment {
        NODE_ENV = 'test'
        MOCK_MODE = 'true'
        PORT = '3001'
        ML_SERVICE_PORT = '5002'
        OPENAI_API_KEY = credentials('openai-api-key')
    }

    options {
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timestamps()
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                sh '''
                    set -e
                    echo "Branch: ${BRANCH_NAME:-unknown}"
                    echo "Build: ${BUILD_NUMBER:-local}"
                    git rev-parse --short HEAD
                '''
            }
        }

        stage('Environment Validation') {
            steps {
                sh '''
                    set -e
                    command -v node >/dev/null 2>&1 || { echo "Required tool not found: node"; exit 1; }
                    command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1 || { echo "Required tool not found: python"; exit 1; }
                    command -v go >/dev/null 2>&1 || { echo "Required tool not found: go"; exit 1; }
                    node --version
                    if command -v python3 >/dev/null 2>&1; then python3 --version; else python --version; fi
                    go version
                '''
            }
        }

        stage('Install Dependencies') {
            parallel {
                stage('Node.js') {
                    steps {
                        sh 'npm ci'
                    }
                }
                stage('Python') {
                    steps {
                        dir('ml-service') {
                            sh '''
                                set -e
                                if command -v python3 >/dev/null 2>&1; then PYTHON_BIN=python3; else PYTHON_BIN=python; fi
                                "$PYTHON_BIN" -m pip install -r requirements.txt --break-system-packages
                            '''
                        }
                    }
                }
                stage('Go') {
                    steps {
                        dir('log-ingestor') {
                            sh 'go mod download && go mod verify'
                        }
                    }
                }
            }
        }

        stage('Static Analysis') {
            parallel {
                stage('Node.js Syntax') {
                    steps {
                        sh '''
                            set -e
                            find src tests scripts -name "*.js" -print0 | xargs -0 -n1 node --check
                            if grep -R -E "sk-[A-Za-z0-9]{20,}" src 2>/dev/null; then
                                echo "Potential hardcoded OpenAI key found"
                                exit 1
                            fi
                        '''
                    }
                }
                stage('Python Syntax') {
                    steps {
                        sh '''
                            set -e
                            if command -v python3 >/dev/null 2>&1; then PYTHON_BIN=python3; else PYTHON_BIN=python; fi
                            "$PYTHON_BIN" -m py_compile \
                                ml-service/app.py \
                                ml-service/models/anomaly_detector.py \
                                ml-service/models/log_vectorizer.py \
                                ml-service/tests/test_scorer.py
                        '''
                    }
                }
                stage('Go Build') {
                    steps {
                        dir('log-ingestor') {
                            sh 'go build ./... && go vet ./...'
                        }
                    }
                }
            }
        }

        stage('Unit Tests') {
            environment {
                MOCK_MODE = 'true'
            }
            parallel {
                stage('Node.js Unit Tests') {
                    steps {
                        sh 'node tests/run-all.js'
                    }
                }
                stage('Python Unit Tests') {
                    steps {
                        dir('ml-service') {
                            sh '''
                                set -e
                                if command -v python3 >/dev/null 2>&1; then PYTHON_BIN=python3; else PYTHON_BIN=python; fi
                                if "$PYTHON_BIN" -c "import pytest" >/dev/null 2>&1; then
                                    "$PYTHON_BIN" -m pytest tests/ -v --tb=short
                                else
                                    "$PYTHON_BIN" -m unittest discover -s tests -p "test_*.py"
                                fi
                            '''
                        }
                    }
                }
                stage('Go Unit Tests') {
                    steps {
                        dir('log-ingestor') {
                            sh 'go test ./... -v -count=1'
                        }
                    }
                }
            }
        }

        stage('Integration Health Check') {
            steps {
                sh '''
                    set -e
                    mkdir -p logs
                    chmod +x .jenkins/scripts/health-check.sh .jenkins/scripts/run-tests.sh
                    cleanup() {
                        if [ -f .jenkins/aegis.pid ]; then
                            kill "$(cat .jenkins/aegis.pid)" 2>/dev/null || true
                            rm -f .jenkins/aegis.pid
                        fi
                    }
                    trap cleanup EXIT
                    MOCK_MODE=true PORT=3001 NODE_ENV=test node src/index.js > logs/jenkins-health-node.log 2>&1 &
                    echo "$!" > .jenkins/aegis.pid
                    sleep 5
                    .jenkins/scripts/health-check.sh 3001 15
                '''
            }
        }

        stage('Scenario Smoke Test') {
            steps {
                sh '''
                    set -e
                    mkdir -p logs
                    chmod +x .jenkins/scripts/health-check.sh .jenkins/scripts/run-tests.sh
                    cleanup() {
                        if [ -f .jenkins/aegis.pid ]; then
                            kill "$(cat .jenkins/aegis.pid)" 2>/dev/null || true
                            rm -f .jenkins/aegis.pid
                        fi
                    }
                    trap cleanup EXIT
                    MOCK_MODE=true PORT=3001 NODE_ENV=test node src/index.js > logs/jenkins-scenarios-node.log 2>&1 &
                    echo "$!" > .jenkins/aegis.pid
                    sleep 5
                    .jenkins/scripts/health-check.sh 3001 15
                    .jenkins/scripts/run-tests.sh
                '''
            }
        }

        stage('Build Summary') {
            steps {
                echo '=== AEGIS Build Summary ==='
                echo 'Node.js: PASS | Python ML: PASS | Go Ingestor: PASS | CI/CD: PASS'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'logs/*.log,ml-service/models/saved_model.pkl', allowEmptyArchive: true
        }
        success {
            echo 'Build SUCCESSFUL. AEGIS ready for deployment.'
        }
        failure {
            echo 'Build FAILED. Review stage logs.'
        }
    }
}
