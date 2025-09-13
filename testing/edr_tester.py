#!/usr/bin/env python3
import os
import sys
import time
import json
import hashlib
from datetime import datetime
from av_engines import AVEngineManager

class EDRTester:
    def __init__(self, test_dir="./test_results"):
        self.test_dir = test_dir
        self.engine_manager = AVEngineManager()
        self.ensure_test_directory()
        
    def ensure_test_directory(self):
        if not os.path.exists(self.test_dir):
            os.makedirs(self.test_dir)
    
    def test_payload(self, payload_path, include_virustotal=False, vt_api_key=None):
        if not os.path.exists(payload_path):
            print(f"Error: Payload {payload_path} not found")
            return None
        
        print(f"Testing payload: {payload_path}")
        print(f"File size: {os.path.getsize(payload_path):,} bytes")
        print(f"SHA256: {self.get_file_hash(payload_path)}")
        print("-" * 60)
        
        results = []
        
        for engine_name in self.engine_manager.get_available_engines():
            print(f"Testing with {engine_name}...")
            result = self.engine_manager.scan_with_engine(engine_name, payload_path)
            results.append(result)
            
            print(f"  Result: {'DETECTED' if result.detected else 'CLEAN'}")
            if result.detection_name:
                print(f"  Detection: {result.detection_name}")
            if result.error:
                print(f"  Error: {result.error}")
            print()
        
        if include_virustotal and vt_api_key:
            print("Testing with VirusTotal...")
            self.engine_manager.add_virustotal(vt_api_key)
            vt_result = self.engine_manager.scan_with_engine('virustotal', payload_path, timeout=300)
            results.append(vt_result)
            
            if not vt_result.error:
                print(f"  Detection Rate: {vt_result.confidence:.1f}%")
                if vt_result.metadata:
                    stats = vt_result.metadata.get('stats', {})
                    print(f"  Engines Detected: {stats.get('malicious', 0)}/{vt_result.metadata.get('total_engines', 0)}")
            else:
                print(f"  Error: {vt_result.error}")
            print()
        
        self.save_results(results, payload_path)
        self.print_summary(results)
        return results
    
    def get_file_hash(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return "unknown"
    
    def save_results(self, results, payload_path):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"test_results_{os.path.basename(payload_path)}_{timestamp}.json"
        
        result_data = {
            "payload_path": payload_path,
            "test_timestamp": datetime.now().isoformat(),
            "file_hash": self.get_file_hash(payload_path),
            "file_size": os.path.getsize(payload_path),
            "results": []
        }
        
        for result in results:
            result_data["results"].append({
                "engine_name": result.engine_name,
                "detected": result.detected,
                "detection_name": result.detection_name,
                "confidence": result.confidence,
                "scan_time": result.scan_time,
                "error": result.error,
                "metadata": result.metadata
            })
        
        output_path = os.path.join(self.test_dir, filename)
        with open(output_path, 'w') as f:
            json.dump(result_data, f, indent=2, default=str)
        
        print(f"Results saved to: {output_path}")
    
    def print_summary(self, results):
        print("=" * 60)
        print("SUMMARY")
        print("=" * 60)
        
        total_engines = len([r for r in results if not r.error])
        detected_count = len([r for r in results if r.detected and not r.error])
        
        if total_engines > 0:
            detection_rate = (detected_count / total_engines) * 100
            print(f"Detection Rate: {detected_count}/{total_engines} ({detection_rate:.1f}%)")
            print(f"Evasion Rate: {total_engines - detected_count}/{total_engines} ({100 - detection_rate:.1f}%)")
        
        print("\nEngine Results:")
        for result in results:
            status = "ERROR" if result.error else ("DETECTED" if result.detected else "CLEAN")
            print(f"  {result.engine_name}: {status}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="EDR Testing Framework")
    parser.add_argument("payload", help="Path to payload file to test")
    parser.add_argument("--virustotal", action="store_true", help="Include VirusTotal testing")
    parser.add_argument("--vt-api-key", help="VirusTotal API key")
    parser.add_argument("--output-dir", default="./test_results", help="Output directory")
    
    args = parser.parse_args()
    
    vt_api_key = args.vt_api_key or os.environ.get('VT_API_KEY')
    
    tester = EDRTester(args.output_dir)
    results = tester.test_payload(args.payload, args.virustotal, vt_api_key)
    
    if results:
        detection_count = len([r for r in results if r.detected and not r.error])
        total_count = len([r for r in results if not r.error])
        print(f"\nFinal Result: {detection_count}/{total_count} engines detected the payload")
        sys.exit(1 if detection_count > 0 else 0)
    else:
        sys.exit(2)

if __name__ == "__main__":
    main()
