import { useState } from "react";
import { Card, CardHeader, CardTitle, CardContent, CardDescription, CardFooter } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { useAuth } from "../context/AuthContext";
import { toast } from "sonner";
import {
  Box,
  Server,
  Shield,
  Terminal,
  CheckCircle,
  XCircle,
  ExternalLink,
  Copy,
  AlertTriangle,
  Cpu,
  HardDrive,
  Lock
} from "lucide-react";

const rawBackendUrl = process.env.REACT_APP_BACKEND_URL?.trim();
const API_URL = rawBackendUrl || "";
const API_ROOT = API_URL ? `${API_URL}/api` : '/api';

export default function SetupGuidePage() {
  const { token } = useAuth();
  const [activeTab, setActiveTab] = useState("cuckoo");

  const copyToClipboard = (text, name) => {
    navigator.clipboard.writeText(text);
    toast.success(`${name} copied to clipboard`);
  };

  const cuckooDockerCompose = `version: '3.8'

services:
  cuckoo:
    image: blacktop/cuckoo:2.0.7
    container_name: cuckoo-sandbox
    privileged: true
    ports:
      - "8090:8090"  # Cuckoo API
      - "2042:2042"  # Cuckoo Agent
    volumes:
      - ./cuckoo-data:/cuckoo
      - /tmp:/tmp
    environment:
      - CUCKOO_API_HOST=0.0.0.0
    networks:
      - cuckoo-network
    restart: unless-stopped

  cuckoo-web:
    image: blacktop/cuckoo:2.0.7
    container_name: cuckoo-web
    command: web
    ports:
      - "8080:8080"
    environment:
      - CUCKOO_API=http://cuckoo:8090
    depends_on:
      - cuckoo
    networks:
      - cuckoo-network
    restart: unless-stopped

  mongodb:
    image: mongo:4.4
    container_name: cuckoo-mongo
    volumes:
      - cuckoo-mongo-data:/data/db
    networks:
      - cuckoo-network
    restart: unless-stopped

networks:
  cuckoo-network:
    driver: bridge

volumes:
  cuckoo-mongo-data:`;

  const cuckooEnvConfig = `# Add these to your backend/.env file
CUCKOO_API_URL=http://localhost:8090
CUCKOO_API_TOKEN=your-api-token-here
CUCKOO_API_VERSION=2
CUCKOO_TIMEOUT=300
CUCKOO_MACHINE=  # Leave empty for auto-selection
CUCKOO_PLATFORM=windows`;

  const liboqsInstall = `# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y cmake ninja-build libssl-dev python3-dev

# Clone and build liboqs
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON ..
ninja
sudo ninja install

# Update library cache
sudo ldconfig

# Install Python bindings
pip install liboqs-python

# Verify installation
python3 -c "import oqs; print('liboqs version:', oqs.oqs_version())"`;

  const liboqsDockerfile = `FROM python:3.11-slim

# Install build dependencies
RUN apt-get update && apt-get install -y \\
    cmake \\
    ninja-build \\
    libssl-dev \\
    git \\
    && rm -rf /var/lib/apt/lists/*

# Build liboqs
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /liboqs \\
    && cd /liboqs \\
    && mkdir build && cd build \\
    && cmake -GNinja -DBUILD_SHARED_LIBS=ON .. \\
    && ninja \\
    && ninja install \\
    && ldconfig

# Install Python bindings
RUN pip install liboqs-python

# Verify
RUN python3 -c "import oqs; print('liboqs ready')"

# Your application
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .

CMD ["python", "server.py"]`;

  const verifyInstallation = async (service) => {
    try {
      const endpoint = service === "cuckoo" 
        ? `${API_ROOT}/advanced/sandbox/status`
        : `${API_ROOT}/advanced/quantum/status`;
      
      const response = await fetch(endpoint, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      if (response.ok) {
        const data = await response.json();
        if (service === "cuckoo") {
          if (data.enabled) {
            toast.success(`Cuckoo Sandbox connected! Mode: ${data.mode}`);
          } else {
            toast.warning("Cuckoo Sandbox not configured - using static analysis fallback");
          }
        } else {
          toast.success(`Quantum Security active! Mode: ${data.mode}`);
          if (data.mode === "simulation") {
            toast.info("Install liboqs for production quantum crypto");
          }
        }
      } else {
        toast.error("Service check failed");
      }
    } catch (error) {
      toast.error(`Failed to check ${service}: ${error.message}`);
    }
  };

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Server className="w-6 h-6 text-cyan-500" />
            Setup Guide
          </h1>
          <p className="text-slate-400">Installation guides for Cuckoo Sandbox and Post-Quantum Cryptography</p>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="bg-slate-900/50 border border-slate-800">
          <TabsTrigger value="cuckoo" data-testid="tab-cuckoo">
            <Box className="w-4 h-4 mr-2" />
            Cuckoo Sandbox
          </TabsTrigger>
          <TabsTrigger value="quantum" data-testid="tab-quantum">
            <Lock className="w-4 h-4 mr-2" />
            Quantum Crypto (liboqs)
          </TabsTrigger>
        </TabsList>

        {/* Cuckoo Sandbox Setup */}
        <TabsContent value="cuckoo">
          <div className="space-y-6">
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Box className="w-5 h-5 text-orange-400" />
                  Cuckoo Sandbox Installation
                </CardTitle>
                <CardDescription>
                  VM-based malware analysis sandbox for deep behavioral analysis
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="p-4 bg-blue-900/20 border border-blue-700/50 rounded-lg">
                  <div className="flex items-start gap-3">
                    <AlertTriangle className="w-5 h-5 text-blue-500 mt-0.5" />
                    <div>
                      <h5 className="text-blue-400 font-medium">Requirements</h5>
                      <ul className="text-sm text-slate-300 mt-2 space-y-1">
                        <li>• Linux host (Ubuntu 20.04+ recommended)</li>
                        <li>• At least 8GB RAM (16GB recommended)</li>
                        <li>• 100GB+ disk space</li>
                        <li>• VT-x/AMD-V virtualization enabled</li>
                        <li>• Windows VM image for analysis</li>
                      </ul>
                    </div>
                  </div>
                </div>

                <div className="space-y-3">
                  <h4 className="text-white font-medium flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-green-400" />
                    Option 1: Docker Deployment (Recommended)
                  </h4>
                  <div className="relative">
                    <pre className="bg-slate-950 p-4 rounded-lg overflow-x-auto text-sm text-slate-300 font-mono max-h-[400px]">
                      {cuckooDockerCompose}
                    </pre>
                    <Button 
                      variant="outline" 
                      size="sm" 
                      className="absolute top-2 right-2"
                      onClick={() => copyToClipboard(cuckooDockerCompose, "docker-compose.yml")}
                    >
                      <Copy className="w-4 h-4" />
                    </Button>
                  </div>
                  <p className="text-sm text-slate-400">
                    Save as <code className="bg-slate-800 px-1 rounded">docker-compose.yml</code> and run: <code className="bg-slate-800 px-1 rounded">docker-compose up -d</code>
                  </p>
                </div>

                <div className="space-y-3">
                  <h4 className="text-white font-medium flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-yellow-400" />
                    Option 2: Native Installation
                  </h4>
                  <ol className="list-decimal list-inside text-slate-300 space-y-2 text-sm">
                    <li>Install dependencies: <code className="bg-slate-800 px-1 rounded">sudo apt install python3-pip mongodb virtualbox</code></li>
                    <li>Install Cuckoo: <code className="bg-slate-800 px-1 rounded">pip3 install cuckoo</code></li>
                    <li>Initialize: <code className="bg-slate-800 px-1 rounded">cuckoo init</code></li>
                    <li>Configure VM in <code className="bg-slate-800 px-1 rounded">~/.cuckoo/conf/virtualbox.conf</code></li>
                    <li>Start: <code className="bg-slate-800 px-1 rounded">cuckoo -d && cuckoo web</code></li>
                  </ol>
                </div>

                <div className="space-y-3">
                  <h4 className="text-white font-medium">Environment Configuration</h4>
                  <div className="relative">
                    <pre className="bg-slate-950 p-4 rounded-lg overflow-x-auto text-sm text-slate-300 font-mono">
                      {cuckooEnvConfig}
                    </pre>
                    <Button 
                      variant="outline" 
                      size="sm" 
                      className="absolute top-2 right-2"
                      onClick={() => copyToClipboard(cuckooEnvConfig, "Cuckoo config")}
                    >
                      <Copy className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              </CardContent>
              <CardFooter className="flex justify-between">
                <a 
                  href="https://cuckoosandbox.org/docs/" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-sm"
                >
                  <ExternalLink className="w-4 h-4" />
                  Official Documentation
                </a>
                <Button onClick={() => verifyInstallation("cuckoo")} data-testid="verify-cuckoo-btn">
                  <CheckCircle className="w-4 h-4 mr-2" />
                  Verify Installation
                </Button>
              </CardFooter>
            </Card>
          </div>
        </TabsContent>

        {/* Quantum Crypto Setup */}
        <TabsContent value="quantum">
          <div className="space-y-6">
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Lock className="w-5 h-5 text-purple-400" />
                  Post-Quantum Cryptography (liboqs)
                </CardTitle>
                <CardDescription>
                  NIST-standardized quantum-resistant algorithms for production security
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <Card className="bg-slate-800/50 border-slate-700">
                    <CardContent className="pt-6">
                      <div className="flex items-center gap-3">
                        <div className="p-2 bg-purple-500/10 rounded-lg">
                          <Shield className="w-6 h-6 text-purple-400" />
                        </div>
                        <div>
                          <h4 className="text-white font-medium">KYBER</h4>
                          <p className="text-sm text-slate-400">Key Encapsulation</p>
                        </div>
                      </div>
                      <p className="text-xs text-slate-500 mt-3">
                        NIST-selected KEM for secure key exchange
                      </p>
                    </CardContent>
                  </Card>

                  <Card className="bg-slate-800/50 border-slate-700">
                    <CardContent className="pt-6">
                      <div className="flex items-center gap-3">
                        <div className="p-2 bg-blue-500/10 rounded-lg">
                          <Cpu className="w-6 h-6 text-blue-400" />
                        </div>
                        <div>
                          <h4 className="text-white font-medium">DILITHIUM</h4>
                          <p className="text-sm text-slate-400">Digital Signatures</p>
                        </div>
                      </div>
                      <p className="text-xs text-slate-500 mt-3">
                        NIST-selected signature scheme
                      </p>
                    </CardContent>
                  </Card>

                  <Card className="bg-slate-800/50 border-slate-700">
                    <CardContent className="pt-6">
                      <div className="flex items-center gap-3">
                        <div className="p-2 bg-green-500/10 rounded-lg">
                          <HardDrive className="w-6 h-6 text-green-400" />
                        </div>
                        <div>
                          <h4 className="text-white font-medium">SHA3-256</h4>
                          <p className="text-sm text-slate-400">Quantum-Safe Hash</p>
                        </div>
                      </div>
                      <p className="text-xs text-slate-500 mt-3">
                        Grover-resistant hashing
                      </p>
                    </CardContent>
                  </Card>
                </div>

                <div className="p-4 bg-yellow-900/20 border border-yellow-700/50 rounded-lg">
                  <div className="flex items-start gap-3">
                    <AlertTriangle className="w-5 h-5 text-yellow-500 mt-0.5" />
                    <div>
                      <h5 className="text-yellow-400 font-medium">Current Mode</h5>
                      <p className="text-sm text-slate-300 mt-1">
                        Seraph AI includes a simulation mode that works without liboqs installed.
                        For production-grade quantum security, install liboqs using the instructions below.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="space-y-3">
                  <h4 className="text-white font-medium flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-green-400" />
                    Native Installation (Ubuntu/Debian)
                  </h4>
                  <div className="relative">
                    <pre className="bg-slate-950 p-4 rounded-lg overflow-x-auto text-sm text-slate-300 font-mono max-h-[300px]">
                      {liboqsInstall}
                    </pre>
                    <Button 
                      variant="outline" 
                      size="sm" 
                      className="absolute top-2 right-2"
                      onClick={() => copyToClipboard(liboqsInstall, "Installation commands")}
                    >
                      <Copy className="w-4 h-4" />
                    </Button>
                  </div>
                </div>

                <div className="space-y-3">
                  <h4 className="text-white font-medium flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-blue-400" />
                    Docker Integration
                  </h4>
                  <div className="relative">
                    <pre className="bg-slate-950 p-4 rounded-lg overflow-x-auto text-sm text-slate-300 font-mono max-h-[300px]">
                      {liboqsDockerfile}
                    </pre>
                    <Button 
                      variant="outline" 
                      size="sm" 
                      className="absolute top-2 right-2"
                      onClick={() => copyToClipboard(liboqsDockerfile, "Dockerfile")}
                    >
                      <Copy className="w-4 h-4" />
                    </Button>
                  </div>
                </div>

                <div className="p-4 bg-slate-800/50 rounded-lg">
                  <h4 className="text-white font-medium mb-3">Supported Algorithms</h4>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <h5 className="text-purple-400 mb-2">Key Encapsulation (KEM)</h5>
                      <ul className="text-slate-300 space-y-1">
                        <li>• Kyber-512 (NIST Level 1)</li>
                        <li>• Kyber-768 (NIST Level 3)</li>
                        <li>• Kyber-1024 (NIST Level 5)</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="text-blue-400 mb-2">Digital Signatures</h5>
                      <ul className="text-slate-300 space-y-1">
                        <li>• Dilithium-2 (NIST Level 2)</li>
                        <li>• Dilithium-3 (NIST Level 3)</li>
                        <li>• Dilithium-5 (NIST Level 5)</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </CardContent>
              <CardFooter className="flex justify-between">
                <a 
                  href="https://openquantumsafe.org/" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-sm"
                >
                  <ExternalLink className="w-4 h-4" />
                  Open Quantum Safe Project
                </a>
                <Button onClick={() => verifyInstallation("quantum")} data-testid="verify-quantum-btn">
                  <CheckCircle className="w-4 h-4 mr-2" />
                  Verify Installation
                </Button>
              </CardFooter>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
