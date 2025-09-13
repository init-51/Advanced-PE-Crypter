"""
AV Engine Interface Classes
Provides standardized interfaces for testing various AV/EDR solutions
"""

import subprocess
import time
import json
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Any

@dataclass
class DetectionResult:
    engine_name: str
    detected: bool
    detection_name: Optional[str] = None
    confidence: Optional[float] = None
    scan_time: Optional[float] = None
    error: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class WindowsDefenderEngine:
    """Windows Defender interface"""
    
    def __init__(self):
        self.engine_name = "Windows Defender"
        # Try multiple possible paths for MpCmdRun.exe
        self.possible_paths = [
            r"C:\Program Files\Windows Defender\MpCmdRun.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2008.9-0\MpCmdRun.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2001.10-0\MpCmdRun.exe"
        ]
        self.mpcmdrun_path = self._find_mpcmdrun()
    
    def _find_mpcmdrun(self):
        """Find MpCmdRun.exe in possible locations"""
        for path in self.possible_paths:
            if os.path.exists(path):
                return path
        return None
    
    def is_available(self) -> bool:
        return self.mpcmdrun_path is not None
    
    def scan_file(self, file_path: str, timeout: int = 60) -> DetectionResult:
        if not self.is_available():
            return DetectionResult(
                self.engine_name, 
                False, 
                error="Windows Defender MpCmdRun.exe not found"
            )
        
        start_time = time.time()
        
        try:
            cmd = [
                self.mpcmdrun_path,
                "-Scan", "-ScanType", "3", "-File", file_path
            ]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            scan_time = time.time() - start_time
            
            # Parse output - Windows Defender returns 2 if threats found
            detected = result.returncode == 2 or "threat" in result.stdout.lower()
            detection_name = None
            
            if detected:
                # Try to extract threat name
                lines = result.stdout.split('\n')
                for line in lines:
                    line = line.strip()
                    if "threat" in line.lower() and "found" in line.lower():
                        detection_name = line
                        break
                if not detection_name:
                    detection_name = "Generic threat detected"
            
            return DetectionResult(
                engine_name=self.engine_name,
                detected=detected,
                detection_name=detection_name,
                scan_time=scan_time,
                metadata={
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
            )
            
        except subprocess.TimeoutExpired:
            return DetectionResult(
                self.engine_name, 
                False, 
                error="Scan timeout after {} seconds".format(timeout),
                scan_time=timeout
            )
        except FileNotFoundError:
            return DetectionResult(
                self.engine_name,
                False,
                error="MpCmdRun.exe not found or not accessible"
            )
        except Exception as e:
            return DetectionResult(
                self.engine_name, 
                False, 
                error="Scan error: {}".format(str(e)),
                scan_time=time.time() - start_time
            )

class VirusTotalEngine:
    """VirusTotal multi-engine interface"""
    
    def __init__(self, api_key: str):
        self.engine_name = "VirusTotal"
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
    
    def is_available(self) -> bool:
        return bool(self.api_key)
    
    def scan_file(self, file_path: str, timeout: int = 300) -> DetectionResult:
        if not self.is_available():
            return DetectionResult(
                self.engine_name, 
                False, 
                error="VirusTotal API key not provided"
            )
        
        try:
            import requests
        except ImportError:
            return DetectionResult(
                self.engine_name,
                False,
                error="requests library not installed. Run: pip install requests"
            )
        
        start_time = time.time()
        
        try:
            # Upload file
            print("  Uploading to VirusTotal...")
            with open(file_path, 'rb') as f:
                files = {'file': f}
                headers = {'x-apikey': self.api_key}
                
                upload_response = requests.post(
                    f"{self.base_url}/files",
                    files=files,
                    headers=headers,
                    timeout=60
                )
                
                if upload_response.status_code == 200:
                    analysis_id = upload_response.json()['data']['id']
                elif upload_response.status_code == 429:
                    return DetectionResult(
                        self.engine_name,
                        False,
                        error="VirusTotal API rate limit exceeded"
                    )
                else:
                    return DetectionResult(
                        self.engine_name,
                        False,
                        error=f"Upload failed: HTTP {upload_response.status_code}"
                    )
                
                print("  Waiting for analysis...")
                
                # Wait for analysis completion
                max_wait = 120  # 2 minutes max
                wait_time = 0
                
                while wait_time < max_wait:
                    time.sleep(10)
                    wait_time += 10
                    
                    try:
                        analysis_response = requests.get(
                            f"{self.base_url}/analyses/{analysis_id}",
                            headers=headers,
                            timeout=30
                        )
                        
                        if analysis_response.status_code == 200:
                            analysis_data = analysis_response.json()
                            status = analysis_data['data']['attributes']['status']
                            
                            if status == 'completed':
                                stats = analysis_data['data']['attributes']['stats']
                                
                                malicious_count = stats.get('malicious', 0)
                                suspicious_count = stats.get('suspicious', 0)  
                                total_engines = sum(stats.values())
                                
                                detected = malicious_count > 0
                                detection_rate = (malicious_count / total_engines * 100) if total_engines > 0 else 0
                                
                                return DetectionResult(
                                    engine_name=self.engine_name,
                                    detected=detected,
                                    confidence=detection_rate,
                                    scan_time=time.time() - start_time,
                                    metadata={
                                        'stats': stats,
                                        'malicious': malicious_count,
                                        'suspicious': suspicious_count,
                                        'total_engines': total_engines,
                                        'analysis_id': analysis_id
                                    }
                                )
                            else:
                                print(f"    Analysis status: {status}")
                        else:
                            print(f"    Analysis check failed: HTTP {analysis_response.status_code}")
                            
                    except requests.RequestException as e:
                        print(f"    Network error checking analysis: {e}")
                        continue
                
                return DetectionResult(
                    self.engine_name,
                    False,
                    error=f"Analysis timeout after {max_wait} seconds",
                    scan_time=time.time() - start_time
                )
                
        except requests.RequestException as e:
            return DetectionResult(
                self.engine_name,
                False,
                error=f"Network error: {str(e)}",
                scan_time=time.time() - start_time
            )
        except Exception as e:
            return DetectionResult(
                self.engine_name,
                False,
                error=f"Unexpected error: {str(e)}",
                scan_time=time.time() - start_time
            )

class AVEngineManager:
    """Manages multiple AV engines"""
    
    def __init__(self):
        self.engines = {}
        self._initialize_engines()
    
    def _initialize_engines(self):
        """Initialize available AV engines"""
        # Windows Defender
        wd = WindowsDefenderEngine()
        if wd.is_available():
            self.engines['windows_defender'] = wd
    
    def add_virustotal(self, api_key: str):
        """Add VirusTotal engine with API key"""
        if api_key:
            vt = VirusTotalEngine(api_key)
            if vt.is_available():
                self.engines['virustotal'] = vt
    
    def get_available_engines(self) -> List[str]:
        """Get list of available engine names"""
        return list(self.engines.keys())
    
    def scan_with_engine(self, engine_name: str, file_path: str, timeout: int = 60) -> DetectionResult:
        """Scan file with specific engine"""
        if engine_name not in self.engines:
            return DetectionResult(
                engine_name, 
                False, 
                error=f"Engine '{engine_name}' not available"
            )
        
        return self.engines[engine_name].scan_file(file_path, timeout)
    
    def scan_with_all_engines(self, file_path: str, timeout: int = 60) -> List[DetectionResult]:
        """Scan file with all available engines"""
        results = []
        
        for engine_name, engine in self.engines.items():
            print(f"Scanning with {engine_name}...")
            result = engine.scan_file(file_path, timeout)
            results.append(result)
        
        return results

# Test functionality when run directly
if __name__ == "__main__":
    import sys
    
    manager = AVEngineManager()
    
    print("=== AV Engine Manager Test ===")
    print("Available AV engines:")
    available_engines = manager.get_available_engines()
    
    if available_engines:
        for engine in available_engines:
            print(f"  ✅ {engine}")
    else:
        print("  ⚠️  No local AV engines detected")
        print("  💡 This is normal on non-Windows systems or if Windows Defender is disabled")
    
    # Add VirusTotal if API key available
    vt_api_key = os.environ.get('VT_API_KEY')
    if vt_api_key:
        manager.add_virustotal(vt_api_key)
        print("  ✅ virustotal (API key detected)")
    else:
        print("  ⚠️  virustotal (no API key - set VT_API_KEY environment variable)")
    
    # Test scan if file provided
    if len(sys.argv) > 1:
        test_file = sys.argv[1]
        if os.path.exists(test_file):
            print(f"\nTesting scan with: {test_file}")
            results = manager.scan_with_all_engines(test_file)
            
            for result in results:
                print(f"\n{result.engine_name}:")
                print(f"  Detected: {result.detected}")
                if result.detection_name:
                    print(f"  Detection: {result.detection_name}")
                if result.confidence is not None:
                    print(f"  Confidence: {result.confidence:.1f}%")
                if result.error:
                    print(f"  Error: {result.error}")
        else:
            print(f"❌ File not found: {test_file}")
    else:
        print("\nUsage: python av_engines.py <file_to_test>")
