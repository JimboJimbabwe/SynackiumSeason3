#!/usr/bin/env python3
import numpy as np
from scipy import stats
from scipy.spatial.distance import mahalanobis
from dataclasses import dataclass
from typing import List, Dict, Tuple
import json
from collections import defaultdict

@dataclass
class PacketSignature:
    """TCP packet-level signature for a request"""
    syn_ack_time: float      # SYN to SYN-ACK (ms)
    wait_time: float         # SYN-ACK to first data (ms)
    ttfb: float              # Total to first byte (ms)
    data_packet_size: int    # Size of first data packet
    tcp_window: int          # TCP window size
    retransmits: int         # Number of retransmissions
    
class ResponseClass:
    """Represents a class of responses with learned distribution"""
    
    def __init__(self, name: str, prior_probability: float):
        self.name = name
        self.prior = prior_probability  # P(class) before seeing data
        
        # Multivariate distribution parameters
        self.mean = None
        self.covariance = None
        self.inv_covariance = None
        
        # Individual signal models (for interpretability)
        self.signal_models = {}
        
    def train(self, samples: List[PacketSignature]):
        """Learn the multivariate distribution from training samples"""
        # Extract feature vectors
        features = np.array([
            [s.wait_time, s.ttfb, s.syn_ack_time, s.data_packet_size]
            for s in samples
        ])
        
        # Calculate mean and covariance
        self.mean = np.mean(features, axis=0)
        self.covariance = np.cov(features, rowvar=False)
        
        # Add small regularization to avoid singular matrix
        self.covariance += np.eye(4) * 0.001
        self.inv_covariance = np.linalg.inv(self.covariance)
        
        # Also train individual Gaussian models for each signal
        signal_names = ['wait_time', 'ttfb', 'syn_ack_time', 'data_packet_size']
        for i, name in enumerate(signal_names):
            values = features[:, i]
            self.signal_models[name] = {
                'mean': np.mean(values),
                'std': np.std(values) + 0.001
            }
        
        print(f"  Trained {self.name}:")
        print(f"    Prior: {self.prior:.2%}")
        print(f"    Mean: wait={self.mean[0]:.2f}ms, ttfb={self.mean[1]:.2f}ms")
    
    def probability_of_signature(self, signature: PacketSignature) -> float:
        """Calculate P(signature | class) using multivariate Gaussian"""
        x = np.array([signature.wait_time, signature.ttfb, 
                     signature.syn_ack_time, signature.data_packet_size])
        
        # Mahalanobis distance
        diff = x - self.mean
        mahal_dist = np.sqrt(np.dot(np.dot(diff, self.inv_covariance), diff))
        
        # Convert to probability (using chi-squared with 4 DOF)
        p_value = stats.chi2.sf(mahal_dist**2, df=4)
        
        # Also calculate individual signal probabilities
        signal_probs = {}
        for name, model in self.signal_models.items():
            value = getattr(signature, name)
            z_score = abs(value - model['mean']) / model['std']
            signal_probs[name] = 2 * (1 - stats.norm.cdf(z_score))
        
        return p_value, signal_probs

class MultiClassBayesianDetector:
    """
    Bayesian detector with multiple learned response classes
    """
    
    def __init__(self):
        self.classes = {}
        
    def add_class(self, name: str, prior_probability: float, 
                  training_samples: List[PacketSignature]):
        """Add a response class with its prior probability"""
        response_class = ResponseClass(name, prior_probability)
        response_class.train(training_samples)
        self.classes[name] = response_class
    
    def classify(self, signature: PacketSignature) -> Dict:
        """
        Returns posterior probabilities for each class
        P(class | signature) ∝ P(signature | class) * P(class)
        """
        posteriors = {}
        likelihoods = {}
        
        # Calculate likelihood for each class
        for class_name, response_class in self.classes.items():
            likelihood, signal_probs = response_class.probability_of_signature(signature)
            likelihoods[class_name] = likelihood
            posteriors[class_name] = likelihood * response_class.prior
        
        # Normalize to get probabilities
        total = sum(posteriors.values())
        if total > 0:
            for class_name in posteriors:
                posteriors[class_name] /= total
        
        # Determine most likely class
        most_likely = max(posteriors, key=posteriors.get)
        confidence = posteriors[most_likely]
        
        # Calculate entropy (uncertainty)
        entropy = -sum(p * np.log(p + 1e-10) for p in posteriors.values())
        
        return {
            'probabilities': posteriors,
            'most_likely': most_likely,
            'confidence': confidence,
            'entropy': entropy,
            'is_anomaly': confidence < 0.5  # Uncertain
        }

class BaselineCollector:
    """
    Collects training data for each response class
    """
    
    def __init__(self, capture_interface="eth0"):
        self.interface = capture_interface
        self.collected_samples = defaultdict(list)
        
    def collect_baseline_200(self, known_endpoints: List[str], samples_per=30):
        """Collect signatures from known working endpoints"""
        print(f"\nCollecting 200 OK baselines from {len(known_endpoints)} endpoints...")
        for endpoint in known_endpoints:
            for _ in range(samples_per):
                sig = self.capture_signature(endpoint)
                if sig.ttfb < 50:  # Filter outliers
                    self.collected_samples['200_OK'].append(sig)
        print(f"  Collected {len(self.collected_samples['200_OK'])} samples")
    
    def collect_baseline_403(self, known_restricted: List[str], samples_per=30):
        """Collect signatures from endpoints that exist but require different method"""
        print(f"\nCollecting 403 baselines...")
        for endpoint in known_restricted:
            for _ in range(samples_per):
                sig = self.capture_signature(endpoint, method='GET')  # Use wrong method
                self.collected_samples['403_Forbidden'].append(sig)
        print(f"  Collected {len(self.collected_samples['403_Forbidden'])} samples")
    
    def collect_baseline_404_immediate(self, random_strings: List[str], samples_per=20):
        """Collect signatures from completely invalid paths (immediate reject)"""
        print(f"\nCollecting 404 (immediate reject) baselines...")
        for random_path in random_strings:
            for _ in range(samples_per):
                sig = self.capture_signature(f"/nonexistent_{random_path}")
                self.collected_samples['404_Immediate'].append(sig)
        print(f"  Collected {len(self.collected_samples['404_Immediate'])} samples")
    
    def collect_baseline_404_partial(self, partial_matches: List[str], samples_per=30):
        """
        CRITICAL: Collect signatures from partial matches
        e.g., "/adm" when "/admin" exists
        """
        print(f"\nCollecting 404 (partial match) baselines...")
        for partial in partial_matches:
            for _ in range(samples_per):
                sig = self.capture_signature(partial)
                self.collected_samples['404_PartialMatch'].append(sig)
        print(f"  Collected {len(self.collected_samples['404_PartialMatch'])} samples")
        print(f"  KEY INSIGHT: wait_time = {np.mean([s.wait_time for s in self.collected_samples['404_PartialMatch']]):.2f}ms")
    
    def capture_signature(self, path: str, method='GET') -> PacketSignature:
        """
        Capture actual packet-level signature
        This is where you'd integrate with tcpdump/tshark
        """
        # For demo, return simulated data based on path patterns
        # In reality, this would capture real packet timings
        
        if "admin" in path and len(path) <= 5:  # Partial match to admin
            return PacketSignature(
                syn_ack_time=1.2,
                wait_time=12.5,    # LONG PAUSE - routing trie traversal!
                ttfb=15.3,
                data_packet_size=512,
                tcp_window=65535,
                retransmits=0
            )
        elif "admin" in path:  # Full match
            return PacketSignature(
                syn_ack_time=1.1,
                wait_time=4.2,     # Medium pause - application routing
                ttfb=6.8,
                data_packet_size=1024,
                tcp_window=65535,
                retransmits=0
            )
        else:  # Immediate 404
            return PacketSignature(
                syn_ack_time=1.0,
                wait_time=1.8,     # NO PAUSE - immediate reject
                ttfb=3.5,
                data_packet_size=256,
                tcp_window=65535,
                retransmits=0
            )

class PrefixEnumeratorWithBaselines:
    """
    Complete enumeration system using multi-class Bayesian detection
    """
    
    def __init__(self, target_base: str):
        self.target_base = target_base
        self.collector = BaselineCollector()
        self.detector = MultiClassBayesianDetector()
        self.prefix_history = {}
        
    def setup_baselines(self):
        """Collect all baseline measurements before enumeration"""
        print("="*60)
        print("SETTING UP BASELINES")
        print("="*60)
        
        # 200 OK - known working endpoints
        self.collector.collect_baseline_200([
            "/api/health",
            "/api/version",
            "/api/status"
        ], samples_per=30)
        
        # 403 Forbidden - known restricted endpoints
        self.collector.collect_baseline_403([
            "/api/admin",
            "/api/config",
            "/api/internal"
        ], samples_per=30)
        
        # 404 Immediate - complete garbage
        self.collector.collect_baseline_404_immediate([
            "xyzabc123", "deadbeef999", "nonexistent_path"
        ], samples_per=20)
        
        # 404 Partial Match - CRITICAL for prefix enumeration!
        # These are prefixes of real endpoints
        self.collector.collect_baseline_404_partial([
            "/adm",      # prefix of /admin
            "/con",      # prefix of /config  
            "/int",      # prefix of /internal
            "/vers"      # prefix of /version
        ], samples_per=30)
        
        # Train detector with all classes
        print("\n" + "="*60)
        print("TRAINING MULTI-CLASS DETECTOR")
        print("="*60)
        
        # Add each class with appropriate prior
        # Prior based on expected distribution during enumeration
        self.detector.add_class(
            '200_OK',
            prior_probability=0.05,  # Rare during enumeration
            training_samples=self.collector.collected_samples['200_OK']
        )
        
        self.detector.add_class(
            '403_Forbidden',
            prior_probability=0.10,  # Uncommon
            training_samples=self.collector.collected_samples['403_Forbidden']
        )
        
        self.detector.add_class(
            '404_PartialMatch',
            prior_probability=0.15,  # More common - these are what we're hunting!
            training_samples=self.collector.collected_samples['404_PartialMatch']
        )
        
        self.detector.add_class(
            '404_Immediate',
            prior_probability=0.70,  # Most common
            training_samples=self.collector.collected_samples['404_Immediate']
        )
        
        print("\nBaseline setup complete!\n")
    
    def test_prefix(self, prefix: str, samples: int = 5) -> Dict:
        """
        Test a prefix and classify using multi-class Bayesian inference
        """
        signatures = []
        
        for i in range(samples):
            # Capture packet signature for this prefix
            sig = self.collector.capture_signature(prefix)
            signatures.append(sig)
        
        # Aggregate signatures (use median for robustness)
        aggregated = PacketSignature(
            syn_ack_time=np.median([s.syn_ack_time for s in signatures]),
            wait_time=np.median([s.wait_time for s in signatures]),
            ttfb=np.median([s.ttfb for s in signatures]),
            data_packet_size=int(np.median([s.data_packet_size for s in signatures])),
            tcp_window=int(np.median([s.tcp_window for s in signatures])),
            retransmits=int(np.median([s.retransmits for s in signatures]))
        )
        
        # Classify
        result = self.detector.classify(aggregated)
        
        # Store with prefix
        self.prefix_history[prefix] = result
        
        return result
    
    def enumerate_depth(self, current_prefix: str, depth: int = 1, max_depth: int = 4):
        """
        Enumerate using Bayesian classification
        """
        if depth > max_depth:
            return []
        
        print(f"\n{'='*60}")
        print(f"DEPTH {depth}: Testing prefixes from '{current_prefix}'")
        print(f"{'='*60}")
        
        candidates = []
        
        for letter in 'abcdefghijklmnopqrstuvwxyz0123456789':
            test_prefix = current_prefix + letter
            print(f"\nTesting: '{test_prefix}'")
            
            # Get classification
            result = self.test_prefix(test_prefix, samples=3)
            
            probs = result['probabilities']
            most_likely = result['most_likely']
            confidence = result['confidence']
            
            print(f"  Classification: {most_likely} (confidence: {confidence:.2%})")
            print(f"    P(404_PartialMatch) = {probs.get('404_PartialMatch', 0):.2%}")
            print(f"    P(403_Forbidden) = {probs.get('403_Forbidden', 0):.2%}")
            print(f"    P(200_OK) = {probs.get('200_OK', 0):.2%}")
            print(f"    P(404_Immediate) = {probs.get('404_Immediate', 0):.2%}")
            
            # Decision logic based on multi-class results
            is_promising = False
            reason = ""
            
            if most_likely == '404_PartialMatch' and confidence > 0.6:
                is_promising = True
                reason = "Partial match detected - likely a real path prefix!"
            elif most_likely == '403_Forbidden' and confidence > 0.7:
                is_promising = True
                reason = "Forbidden - endpoint exists but wrong method"
            elif most_likely == '200_OK' and confidence > 0.8:
                is_promising = True
                reason = "Direct hit - endpoint exists and accessible!"
            elif probs.get('404_PartialMatch', 0) > 0.4:
                is_promising = True
                reason = "Weak partial match signal"
            
            if is_promising:
                print(f"  ✓ PROMISING: {reason}")
                candidates.append((test_prefix, confidence, most_likely))
            else:
                print(f"  ✗ NOT PROMISING")
        
        # Sort by confidence
        candidates.sort(key=lambda x: x[1], reverse=True)
        
        # Explore top candidates deeper
        discovered = []
        for prefix, confidence, class_type in candidates[:3]:
            print(f"\n→ Exploring deeper: '{prefix}' (confidence: {confidence:.2%})")
            
            # Different behavior based on classification
            if class_type == '200_OK':
                # Found full endpoint, no need to go deeper
                discovered.append((prefix, 'FULL_ENDPOINT', confidence))
            elif class_type == '403_Forbidden':
                # Found endpoint but wrong method, still explore deeper paths
                discovered.append((prefix, 'RESTRICTED_ENDPOINT', confidence))
                discovered.extend(self.enumerate_depth(prefix, depth + 1, max_depth))
            else:  # Partial match
                discovered.append((prefix, 'PREFIX', confidence))
                discovered.extend(self.enumerate_depth(prefix, depth + 1, max_depth))
        
        return discovered

# Usage
if __name__ == "__main__":
    enumerator = PrefixEnumeratorWithBaselines("https://example.com/api")
    
    # Step 1: Setup baselines for all response types
    enumerator.setup_baselines()
    
    # Step 2: Enumerate!
    print("\n" + "="*60)
    print("STARTING PREFIX ENUMERATION")
    print("="*60)
    
    discovered = enumerator.enumerate_depth("", depth=1, max_depth=4)
    
    # Step 3: Report results
    print("\n" + "="*60)
    print("ENUMERATION RESULTS")
    print("="*60)
    
    for prefix, type_, confidence in discovered:
        if type_ == 'FULL_ENDPOINT':
            print(f"✓ {prefix:20s} → FULL ENDPOINT (confidence: {confidence:.2%})")
        elif type_ == 'RESTRICTED_ENDPOINT':
            print(f"⚠ {prefix:20s} → RESTRICTED (wrong method) (confidence: {confidence:.2%})")
        else:
            print(f"? {prefix:20s} → PREFIX (explore deeper) (confidence: {confidence:.2%})")
