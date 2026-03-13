#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <ctime>
#include <algorithm>

using namespace std;

// Threat types
enum ThreatLevel {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

struct Packet {
    string sourceIP;
    string destIP;
    int port;
    string protocol;
    int size;
    time_t timestamp;
    string payload;
};

struct Threat {
    string type;
    string description;
    ThreatLevel level;
    string sourceIP;
    time_t detected;
};

class CyberSecurityAnalyzer {
private:
    vector<Packet> packets;
    vector<Threat> threats;
    map<string, int> ipFrequency;
    map<int, int> portScanCount;
    
    // Known malicious ports
    vector<int> suspiciousPorts = {22, 23, 25, 445, 3389, 4444, 5555};
    
public:
    // Add network packet
    void addPacket(string src, string dst, int port, string proto, int size, string payload) {
        Packet p = {src, dst, port, proto, size, time(0), payload};
        packets.push_back(p);
        ipFrequency[src]++;
    }
    
    // Detect port scanning
    void detectPortScan() {
        map<string, vector<int>> ipToPorts;
        
        for (auto& p : packets) {
            ipToPorts[p.sourceIP].push_back(p.port);
        }
        
        for (auto& entry : ipToPorts) {
            // Unique ports accessed by single IP
            sort(entry.second.begin(), entry.second.end());
            auto last = unique(entry.second.begin(), entry.second.end());
            int uniquePorts = distance(entry.second.begin(), last);
            
            if (uniquePorts > 10) { // Threshold
                Threat t;
                t.type = "Port Scan";
                t.description = "Multiple ports accessed: " + to_string(uniquePorts);
                t.level = HIGH;
                t.sourceIP = entry.first;
                t.detected = time(0);
                threats.push_back(t);
            }
        }
    }
    
    // Detect DDoS attack
    void detectDDoS() {
        for (auto& entry : ipFrequency) {
            if (entry.second > 100) { // Threshold: 100+ requests
                Threat t;
                t.type = "Potential DDoS";
                t.description = "High frequency requests: " + to_string(entry.second);
                t.level = CRITICAL;
                t.sourceIP = entry.first;
                t.detected = time(0);
                threats.push_back(t);
            }
        }
    }
    
    // Detect suspicious payload patterns
    void detectMaliciousPayload() {
        vector<string> patterns = {"cmd.exe", "/bin/sh", "DROP", "DELETE", "rm -rf", "<script>"};
        
        for (auto& p : packets) {
            for (auto& pattern : patterns) {
                if (p.payload.find(pattern) != string::npos) {
                    Threat t;
                    t.type = "Malicious Payload";
                    t.description = "Pattern found: " + pattern;
                    t.level = CRITICAL;
                    t.sourceIP = p.sourceIP;
                    t.detected = time(0);
                    threats.push_back(t);
                    break;
                }
            }
        }
    }
    
    // Detect suspicious port access
    void detectSuspiciousPorts() {
        for (auto& p : packets) {
            if (find(suspiciousPorts.begin(), suspiciousPorts.end(), p.port) != suspiciousPorts.end()) {
                Threat t;
                t.type = "Suspicious Port Access";
                t.description = "Accessed port: " + to_string(p.port);
                t.level = MEDIUM;
                t.sourceIP = p.sourceIP;
                t.detected = time(0);
                threats.push_back(t);
            }
        }
    }
    
    // Run all analysis
    void analyze() {
        detectPortScan();
        detectDDoS();
        detectMaliciousPayload();
        detectSuspiciousPorts();
    }
    
    // Generate report
    void generateReport() {
        cout << "\n========== CYBERSECURITY THREAT ANALYSIS REPORT ==========\n";
        cout << "Total Packets Analyzed: " << packets.size() << endl;
        cout << "Total Threats Detected: " << threats.size() << endl;
        
        int critical = 0, high = 0, medium = 0, low = 0;
        
        for (auto& t : threats) {
            switch(t.level) {
                case CRITICAL: critical++; break;
                case HIGH: high++; break;
                case MEDIUM: medium++; break;
                case LOW: low++; break;
            }
        }
        
        cout << "\nThreat Distribution:\n";
        cout << "CRITICAL: " << critical << endl;
        cout << "HIGH: " << high << endl;
        cout << "MEDIUM: " << medium << endl;
        cout << "LOW: " << low << endl;
        
        cout << "\n---------- DETAILED THREATS ----------\n";
        for (auto& t : threats) {
            string levelStr;
            switch(t.level) {
                case CRITICAL: levelStr = "CRITICAL"; break;
                case HIGH: levelStr = "HIGH"; break;
                case MEDIUM: levelStr = "MEDIUM"; break;
                case LOW: levelStr = "LOW"; break;
            }
            
            cout << "[" << levelStr << "] " << t.type << endl;
            cout << "  Source: " << t.sourceIP << endl;
            cout << "  Description: " << t.description << endl;
            cout << "  Time: " << ctime(&t.detected);
            cout << endl;
        }
        
        // Recommendations
        cout << "---------- RECOMMENDATIONS ----------\n";
        if (critical > 0) {
            cout << "IMMEDIATE ACTION REQUIRED!\n";
            cout << "- Block critical threat IPs immediately\n";
            cout << "- Enable emergency firewall rules\n";
        }
        if (high > 0) {
            cout << "- Review high priority threats\n";
            cout << "- Increase monitoring on flagged IPs\n";
        }
        cout << "- Update firewall rules based on detected patterns\n";
        cout << "- Review logs for additional indicators of compromise\n";
    }
};

int main() {
    CyberSecurityAnalyzer analyzer;
    
    // Simulate network traffic (normal + malicious)
    cout << "Simulating network traffic...\n";
    
    // Normal traffic
    for (int i = 0; i < 20; i++) {
        analyzer.addPacket("192.168.1.10", "10.0.0.5", 80, "TCP", 500, "GET /index.html");
    }
    
    // Port scan simulation
    for (int port = 1; port <= 20; port++) {
        analyzer.addPacket("192.168.1.100", "10.0.0.5", port, "TCP", 100, "");
    }
    
    // DDoS simulation
    for (int i = 0; i < 150; i++) {
        analyzer.addPacket("10.0.0.99", "192.168.1.1", 80, "TCP", 1000, "GET /");
    }
    
    // Malicious payload
    analyzer.addPacket("192.168.1.50", "10.0.0.5", 445, "TCP", 200, "cmd.exe /c del *.*");
    analyzer.addPacket("192.168.1.51", "10.0.0.5", 22, "TCP", 150, "rm -rf /");
    
    // Suspicious port access
    analyzer.addPacket("192.168.1.60", "10.0.0.5", 4444, "TCP", 300, "data");
    
    // Run analysis
    analyzer.analyze();
    
    // Generate report
    analyzer.generateReport();
    
    return 0;
}