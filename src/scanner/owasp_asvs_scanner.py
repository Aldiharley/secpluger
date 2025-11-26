#!/usr/bin/env python3
"""
OWASP ASVS (Application Security Verification Standard) Scanner
Implements comprehensive security testing based on OWASP ASVS 4.0.3

Categories covered:
- V1: Architecture, Design and Threat Modeling
- V2: Authentication
- V3: Session Management
- V4: Access Control
- V5: Validation, Sanitization and Encoding
- V6: Stored Cryptography
- V7: Error Handling and Logging
- V8: Data Protection
- V9: Communication
- V10: Malicious Code
- V11: Business Logic
- V12: Files and Resources
- V13: API and Web Service
- V14: Configuration
"""

import requests
import json
import re
from typing import Dict, List, Optional
from datetime import datetime
import urllib.parse
from pathlib import Path

class OWASPASVSScanner:
    """Comprehensive OWASP ASVS-based security scanner"""
    
    def __init__(self, target_url: str, evidence_dir: Optional[str] = None):
        self.target_url = target_url.rstrip('/')
        self.evidence_dir = evidence_dir or "evidence"
        self.session = requests.Session()
        self.findings = []
        
        # ASVS verification levels
        self.level = 2  # Level 2 = Standard (most web apps)
        
    def scan(self, session_cookies: Optional[Dict] = None, 
             auth_token: Optional[str] = None) -> Dict:
        """
        Perform comprehensive OWASP ASVS scan
        
        Args:
            session_cookies: Authenticated session cookies
            auth_token: Authentication token if needed
        """
        if session_cookies:
            self.session.cookies.update(session_cookies)
        
        print("[*] Starting OWASP ASVS Security Assessment")
        print(f"[*] Target: {self.target_url}")
        print(f"[*] ASVS Level: {self.level}")
        print("="*70)
        
        results = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'asvs_level': self.level,
            'categories': {}
        }
        
        # V1: Architecture, Design and Threat Modeling
        results['categories']['V1_Architecture'] = self._test_architecture()
        
        # V2: Authentication
        results['categories']['V2_Authentication'] = self._test_authentication()
        
        # V3: Session Management
        results['categories']['V3_Session'] = self._test_session_management()
        
        # V4: Access Control
        results['categories']['V4_AccessControl'] = self._test_access_control()
        
        # V5: Validation, Sanitization and Encoding
        results['categories']['V5_Validation'] = self._test_validation()
        
        # V6: Stored Cryptography
        results['categories']['V6_Cryptography'] = self._test_cryptography()
        
        # V7: Error Handling and Logging
        results['categories']['V7_Errors'] = self._test_error_handling()
        
        # V8: Data Protection
        results['categories']['V8_DataProtection'] = self._test_data_protection()
        
        # V9: Communication
        results['categories']['V9_Communication'] = self._test_communication()
        
        # V10: Malicious Code
        results['categories']['V10_MaliciousCode'] = self._test_malicious_code()
        
        # V11: Business Logic
        results['categories']['V11_BusinessLogic'] = self._test_business_logic()
        
        # V12: Files and Resources
        results['categories']['V12_Files'] = self._test_files()
        
        # V13: API and Web Service
        results['categories']['V13_API'] = self._test_api()
        
        # V14: Configuration
        results['categories']['V14_Configuration'] = self._test_configuration()
        
        # Generate summary
        results['summary'] = self._generate_summary(results)
        
        # Save results
        self._save_results(results)
        
        return results
    
    def _test_architecture(self) -> Dict:
        """V1: Architecture, Design and Threat Modeling"""
        print("\n[*] V1: Testing Architecture & Design...")
        findings = []
        
        # V1.1: Secure SDLC
        findings.append({
            'id': 'V1.1.1',
            'title': 'Source Code Exposure Check',
            'severity': 'INFO',
            'test': 'Check for exposed source code archives',
            'result': self._check_source_exposure()
        })
        
        # V1.2: Authentication Architecture
        findings.append({
            'id': 'V1.2.1',
            'title': 'Authentication Components Discovery',
            'severity': 'INFO',
            'test': 'Identify authentication mechanisms',
            'result': self._identify_auth_components()
        })
        
        # V1.4: Access Control Architecture
        findings.append({
            'id': 'V1.4.1',
            'title': 'Authorization Model Detection',
            'severity': 'INFO',
            'test': 'Detect access control implementation',
            'result': self._detect_access_control_model()
        })
        
        # V1.7: Errors, Logging and Auditing
        findings.append({
            'id': 'V1.7.1',
            'title': 'Error Disclosure Analysis',
            'severity': 'LOW',
            'test': 'Check for verbose error messages',
            'result': self._check_error_disclosure()
        })
        
        # V1.14: Configuration Architecture
        findings.append({
            'id': 'V1.14.1',
            'title': 'Configuration File Exposure',
            'severity': 'HIGH',
            'test': 'Check for exposed configuration files',
            'result': self._check_config_exposure()
        })
        
        return {
            'category': 'Architecture, Design and Threat Modeling',
            'findings': findings,
            'score': self._calculate_score(findings)
        }
    
    def _test_authentication(self) -> Dict:
        """V2: Authentication"""
        print("\n[*] V2: Testing Authentication...")
        findings = []
        
        # V2.1: Password Security
        findings.append({
            'id': 'V2.1.1',
            'title': 'Password Policy Detection',
            'severity': 'MEDIUM',
            'test': 'Verify password complexity requirements',
            'result': self._test_password_policy()
        })
        
        findings.append({
            'id': 'V2.1.7',
            'title': 'Password Breach Database Check',
            'severity': 'LOW',
            'test': 'Check if passwords validated against breach databases',
            'result': self._test_breach_detection()
        })
        
        # V2.2: General Authenticator Security
        findings.append({
            'id': 'V2.2.1',
            'title': 'Anti-Automation Controls',
            'severity': 'MEDIUM',
            'test': 'Test for rate limiting and CAPTCHA',
            'result': self._test_anti_automation()
        })
        
        findings.append({
            'id': 'V2.2.3',
            'title': 'Account Enumeration Protection',
            'severity': 'LOW',
            'test': 'Check for username enumeration vulnerabilities',
            'result': self._test_username_enumeration()
        })
        
        # V2.3: Authenticator Lifecycle
        findings.append({
            'id': 'V2.3.1',
            'title': 'Default Credentials Check',
            'severity': 'CRITICAL',
            'test': 'Test for default/common credentials',
            'result': self._test_default_credentials()
        })
        
        # V2.5: Credential Recovery
        findings.append({
            'id': 'V2.5.1',
            'title': 'Password Reset Security',
            'severity': 'HIGH',
            'test': 'Analyze password reset mechanism',
            'result': self._test_password_reset()
        })
        
        # V2.7: Out of Band Verifier
        findings.append({
            'id': 'V2.7.1',
            'title': 'OTP Implementation Check',
            'severity': 'INFO',
            'test': 'Check for OTP/2FA implementation',
            'result': self._test_otp_implementation()
        })
        
        # V2.8: One Time Verifier
        findings.append({
            'id': 'V2.8.1',
            'title': 'OTP Reuse Prevention',
            'severity': 'MEDIUM',
            'test': 'Test if OTPs can be reused',
            'result': self._test_otp_reuse()
        })
        
        # V2.10: Service Authentication
        findings.append({
            'id': 'V2.10.1',
            'title': 'API Authentication Mechanism',
            'severity': 'HIGH',
            'test': 'Verify secure API authentication',
            'result': self._test_api_auth()
        })
        
        return {
            'category': 'Authentication',
            'findings': findings,
            'score': self._calculate_score(findings)
        }
    
    def _test_session_management(self) -> Dict:
        """V3: Session Management"""
        print("\n[*] V3: Testing Session Management...")
        findings = []
        
        # V3.1: Fundamental Session Management Security
        findings.append({
            'id': 'V3.1.1',
            'title': 'Session Token Security',
            'severity': 'HIGH',
            'test': 'Verify session tokens never in URLs',
            'result': self._test_session_in_url()
        })
        
        # V3.2: Session Binding
        findings.append({
            'id': 'V3.2.1',
            'title': 'Session Token Randomness',
            'severity': 'CRITICAL',
            'test': 'Test session token entropy',
            'result': self._test_session_randomness()
        })
        
        findings.append({
            'id': 'V3.2.3',
            'title': 'Session Fixation Protection',
            'severity': 'HIGH',
            'test': 'Check for session fixation vulnerabilities',
            'result': self._test_session_fixation()
        })
        
        # V3.3: Session Timeout
        findings.append({
            'id': 'V3.3.1',
            'title': 'Logout Functionality',
            'severity': 'MEDIUM',
            'test': 'Verify proper logout implementation',
            'result': self._test_logout()
        })
        
        findings.append({
            'id': 'V3.3.2',
            'title': 'Session Timeout',
            'severity': 'LOW',
            'test': 'Check for idle timeout',
            'result': self._test_session_timeout()
        })
        
        # V3.4: Cookie-based Session Management
        findings.append({
            'id': 'V3.4.1',
            'title': 'Cookie Security Flags',
            'severity': 'MEDIUM',
            'test': 'Verify Secure, HttpOnly, SameSite flags',
            'result': self._test_cookie_flags()
        })
        
        findings.append({
            'id': 'V3.4.5',
            'title': 'Cookie Scope',
            'severity': 'LOW',
            'test': 'Check cookie path and domain settings',
            'result': self._test_cookie_scope()
        })
        
        # V3.5: Token-based Session Management
        findings.append({
            'id': 'V3.5.1',
            'title': 'JWT/Token Security',
            'severity': 'HIGH',
            'test': 'Analyze JWT implementation if present',
            'result': self._test_jwt_security()
        })
        
        return {
            'category': 'Session Management',
            'findings': findings,
            'score': self._calculate_score(findings)
        }
    
    def _test_access_control(self) -> Dict:
        """V4: Access Control"""
        print("\n[*] V4: Testing Access Control...")
        findings = []
        
        # V4.1: General Access Control Design
        findings.append({
            'id': 'V4.1.1',
            'title': 'Principle of Least Privilege',
            'severity': 'MEDIUM',
            'test': 'Check if access is deny by default',
            'result': self._test_default_deny()
        })
        
        findings.append({
            'id': 'V4.1.3',
            'title': 'IDOR Protection',
            'severity': 'HIGH',
            'test': 'Test for Insecure Direct Object References',
            'result': self._test_idor()
        })
        
        # V4.2: Operation Level Access Control
        findings.append({
            'id': 'V4.2.1',
            'title': 'Sensitive Data Access Control',
            'severity': 'HIGH',
            'test': 'Verify access controls on sensitive operations',
            'result': self._test_sensitive_operations()
        })
        
        # V4.3: Other Access Control Considerations
        findings.append({
            'id': 'V4.3.1',
            'title': 'Administrative Interface Protection',
            'severity': 'CRITICAL',
            'test': 'Check admin interface access controls',
            'result': self._test_admin_access()
        })
        
        findings.append({
            'id': 'V4.3.2',
            'title': 'Directory Browsing',
            'severity': 'LOW',
            'test': 'Check for directory listing vulnerabilities',
            'result': self._test_directory_browsing()
        })
        
        return {
            'category': 'Access Control',
            'findings': findings,
            'score': self._calculate_score(findings)
        }
    
    def _test_validation(self) -> Dict:
        """V5: Validation, Sanitization and Encoding"""
        print("\n[*] V5: Testing Validation & Encoding...")
        findings = []
        
        # V5.1: Input Validation
        findings.append({
            'id': 'V5.1.1',
            'title': 'Input Validation Implementation',
            'severity': 'HIGH',
            'test': 'Check for whitelist input validation',
            'result': self._test_input_validation()
        })
        
        findings.append({
            'id': 'V5.1.4',
            'title': 'Structured Data Validation',
            'severity': 'MEDIUM',
            'test': 'Test validation of JSON/XML input',
            'result': self._test_structured_data()
        })
        
        # V5.2: Sanitization and Sandboxing
        findings.append({
            'id': 'V5.2.1',
            'title': 'XSS Protection',
            'severity': 'HIGH',
            'test': 'Test for Cross-Site Scripting vulnerabilities',
            'result': self._test_xss()
        })
        
        findings.append({
            'id': 'V5.2.8',
            'title': 'SQL Injection Protection',
            'severity': 'CRITICAL',
            'test': 'Test for SQL injection vulnerabilities',
            'result': self._test_sql_injection()
        })
        
        # V5.3: Output Encoding and Injection Prevention
        findings.append({
            'id': 'V5.3.1',
            'title': 'Context-Aware Output Encoding',
            'severity': 'HIGH',
            'test': 'Verify proper output encoding',
            'result': self._test_output_encoding()
        })
        
        findings.append({
            'id': 'V5.3.3',
            'title': 'Template Injection Protection',
            'severity': 'CRITICAL',
            'test': 'Test for Server-Side Template Injection',
            'result': self._test_ssti()
        })
        
        findings.append({
            'id': 'V5.3.6',
            'title': 'XML Injection Protection',
            'severity': 'HIGH',
            'test': 'Test for XML/XXE vulnerabilities',
            'result': self._test_xxe()
        })
        
        findings.append({
            'id': 'V5.3.10',
            'title': 'Command Injection Protection',
            'severity': 'CRITICAL',
            'test': 'Test for OS command injection',
            'result': self._test_command_injection()
        })
        
        # V5.5: Deserialization Prevention
        findings.append({
            'id': 'V5.5.1',
            'title': 'Insecure Deserialization',
            'severity': 'CRITICAL',
            'test': 'Test for unsafe deserialization',
            'result': self._test_deserialization()
        })
        
        return {
            'category': 'Validation, Sanitization and Encoding',
            'findings': findings,
            'score': self._calculate_score(findings)
        }
    
    def _test_cryptography(self) -> Dict:
        """V6: Stored Cryptography"""
        print("\n[*] V6: Testing Cryptography...")
        findings = []
        
        # V6.2: Algorithms
        findings.append({
            'id': 'V6.2.1',
            'title': 'Approved Cryptographic Algorithms',
            'severity': 'HIGH',
            'test': 'Check for weak cryptographic algorithms',
            'result': self._test_weak_crypto()
        })
        
        findings.append({
            'id': 'V6.2.2',
            'title': 'Random Number Generation',
            'severity': 'HIGH',
            'test': 'Verify cryptographically secure RNG',
            'result': self._test_random_generation()
        })
        
        # V6.3: Random Values
        findings.append({
            'id': 'V6.3.1',
            'title': 'Secret Key Management',
            'severity': 'CRITICAL',
            'test': 'Check for hardcoded secrets',
            'result': self._test_hardcoded_secrets()
        })
        
        # V6.4: Secret Management
        findings.append({
            'id': 'V6.4.1',
            'title': 'Key Rotation',
            'severity': 'MEDIUM',
            'test': 'Check if keys can be rotated',
            'result': self._test_key_rotation()
        })
        
        return {
            'category': 'Stored Cryptography',
            'findings': findings,
            'score': self._calculate_score(findings)
        }
    
    def _test_error_handling(self) -> Dict:
        """V7: Error Handling and Logging"""
        print("\n[*] V7: Testing Error Handling & Logging...")
        findings = []
        
        # V7.1: Log Content
        findings.append({
            'id': 'V7.1.1',
            'title': 'Security Event Logging',
            'severity': 'LOW',
            'test': 'Check if security events are logged',
            'result': self._test_security_logging()
        })
        
        # V7.2: Log Processing
        findings.append({
            'id': 'V7.2.1',
            'title': 'Log Injection Protection',
            'severity': 'LOW',
            'test': 'Test for log injection vulnerabilities',
            'result': self._test_log_injection()
        })
        
        # V7.3: Log Protection
        findings.append({
            'id': 'V7.3.1',
            'title': 'Log Access Control',
            'severity': 'MEDIUM',
            'test': 'Verify log files are protected',
            'result': self._test_log_protection()
        })
        
        # V7.4: Error Handling
        findings.append({
            'id': 'V7.4.1',
            'title': 'Generic Error Messages',
            'severity': 'LOW',
            'test': 'Check for information disclosure in errors',
            'result': self._test_error_messages()
        })
        
        findings.append({
            'id': 'V7.4.3',
            'title': 'Debug Mode Detection',
            'severity': 'MEDIUM',
            'test': 'Check if debug mode is enabled',
            'result': self._test_debug_mode()
        })
        
        return {
            'category': 'Error Handling and Logging',
            'findings': findings,
            'score': self._calculate_score(findings)
        }
    
    def _test_data_protection(self) -> Dict:
        """V8: Data Protection"""
        print("\n[*] V8: Testing Data Protection...")
        findings = []
        
        # V8.1: General Data Protection
        findings.append({
            'id': 'V8.1.1',
            'title': 'Sensitive Data Protection',
            'severity': 'HIGH',
            'test': 'Verify sensitive data is protected at rest',
            'result': self._test_data_at_rest()
        })
        
        # V8.2: Client-side Data Protection
        findings.append({
            'id': 'V8.2.1',
            'title': 'Client-Side Sensitive Data',
            'severity': 'MEDIUM',
            'test': 'Check for sensitive data in client storage',
            'result': self._test_client_storage()
        })
        
        findings.append({
            'id': 'V8.2.2',
            'title': 'Autocomplete on Sensitive Fields',
            'severity': 'LOW',
            'test': 'Verify autocomplete=off on sensitive inputs',
            'result': self._test_autocomplete()
        })
        
        # V8.3: Sensitive Private Data
        findings.append({
            'id': 'V8.3.1',
            'title': 'PII Data Handling',
            'severity': 'HIGH',
            'test': 'Check handling of personally identifiable information',
            'result': self._test_pii_handling()
        })
        
        findings.append({
            'id': 'V8.3.4',
            'title': 'Sensitive Data in Memory',
            'severity': 'LOW',
            'test': 'Check for sensitive data minimization',
            'result': self._test_memory_data()
        })
        
        return {
            'category': 'Data Protection',
            'findings': findings,
            'score': self._calculate_score(findings)
        }
    
    def _test_communication(self) -> Dict:
        """V9: Communication"""
        print("\n[*] V9: Testing Communication Security...")
        findings = []
        
        # V9.1: Client Communication Security
        findings.append({
            'id': 'V9.1.1',
            'title': 'TLS for All Connections',
            'severity': 'CRITICAL',
            'test': 'Verify TLS is used for all connections',
            'result': self._test_tls_usage()
        })
        
        findings.append({
            'id': 'V9.1.2',
            'title': 'TLS Configuration',
            'severity': 'HIGH',
            'test': 'Check TLS version and cipher suites',
            'result': self._test_tls_config()
        })
        
        findings.append({
            'id': 'V9.1.3',
            'title': 'Certificate Validation',
            'severity': 'HIGH',
            'test': 'Verify valid TLS certificates',
            'result': self._test_certificate()
        })
        
        # V9.2: Server Communication Security
        findings.append({
            'id': 'V9.2.1',
            'title': 'Trusted TLS Certificates',
            'severity': 'HIGH',
            'test': 'Check for self-signed certificates',
            'result': self._test_trusted_cert()
        })
        
        findings.append({
            'id': 'V9.2.3',
            'title': 'HTTP Strict Transport Security',
            'severity': 'MEDIUM',
            'test': 'Verify HSTS header is present',
            'result': self._test_hsts()
        })
        
        return {
            'category': 'Communication',
            'findings': findings,
            'score': self._calculate_score(findings)
        }
    
    def _test_malicious_code(self) -> Dict:
        """V10: Malicious Code"""
        print("\n[*] V10: Testing for Malicious Code...")
        findings = []
        
        # V10.2: Malicious Code Search
        findings.append({
            'id': 'V10.2.1',
            'title': 'Code Repository Security',
            'severity': 'INFO',
            'test': 'Check for exposed .git directories',
            'result': self._test_git_exposure()
        })
        
        findings.append({
            'id': 'V10.2.4',
            'title': 'Suspicious Code Patterns',
            'severity': 'HIGH',
            'test': 'Search for suspicious code patterns',
            'result': self._test_suspicious_code()
        })
        
        # V10.3: Application Integrity
        findings.append({
            'id': 'V10.3.1',
            'title': 'Subresource Integrity',
            'severity': 'LOW',
            'test': 'Check for SRI on external resources',
            'result': self._test_subresource_integrity()
        })
        
        findings.append({
            'id': 'V10.3.2',
            'title': 'Client-Side Protection',
            'severity': 'INFO',
            'test': 'Verify client-side code integrity checks',
            'result': self._test_client_integrity()
        })
        
        return {
            'category': 'Malicious Code',
            'findings': findings,
            'score': self._calculate_score(findings)
        }
    
    def _test_business_logic(self) -> Dict:
        """V11: Business Logic"""
        print("\n[*] V11: Testing Business Logic...")
        findings = []
        
        # V11.1: Business Logic Security
        findings.append({
            'id': 'V11.1.1',
            'title': 'Business Logic Flow',
            'severity': 'HIGH',
            'test': 'Test for business logic bypass',
            'result': self._test_business_flow()
        })
        
        findings.append({
            'id': 'V11.1.2',
            'title': 'Transaction Integrity',
            'severity': 'MEDIUM',
            'test': 'Verify transactions occur in correct order',
            'result': self._test_transaction_order()
        })
        
        findings.append({
            'id': 'V11.1.4',
            'title': 'Rate Limiting',
            'severity': 'MEDIUM',
            'test': 'Check for proper rate limiting',
            'result': self._test_rate_limiting()
        })
        
        findings.append({
            'id': 'V11.1.5',
            'title': 'Replay Attack Protection',
            'severity': 'MEDIUM',
            'test': 'Test for replay attack vulnerabilities',
            'result': self._test_replay_protection()
        })
        
        findings.append({
            'id': 'V11.1.8',
            'title': 'Race Condition Protection',
            'severity': 'MEDIUM',
            'test': 'Test for race conditions',
            'result': self._test_race_conditions()
        })
        
        return {
            'category': 'Business Logic',
            'findings': findings,
            'score': self._calculate_score(findings)
        }
    
    def _test_files(self) -> Dict:
        """V12: Files and Resources"""
        print("\n[*] V12: Testing File Handling...")
        findings = []
        
        # V12.1: File Upload
        findings.append({
            'id': 'V12.1.1',
            'title': 'File Type Validation',
            'severity': 'HIGH',
            'test': 'Verify file upload type validation',
            'result': self._test_file_upload_validation()
        })
        
        findings.append({
            'id': 'V12.1.2',
            'title': 'File Size Limits',
            'severity': 'MEDIUM',
            'test': 'Check for file size restrictions',
            'result': self._test_file_size_limits()
        })
        
        findings.append({
            'id': 'V12.1.3',
            'title': 'File Content Validation',
            'severity': 'HIGH',
            'test': 'Verify uploaded file content is validated',
            'result': self._test_file_content_validation()
        })
        
        # V12.3: File Execution
        findings.append({
            'id': 'V12.3.1',
            'title': 'Uploaded File Execution',
            'severity': 'CRITICAL',
            'test': 'Check if uploaded files can be executed',
            'result': self._test_file_execution()
        })
        
        findings.append({
            'id': 'V12.3.2',
            'title': 'Path Traversal',
            'severity': 'HIGH',
            'test': 'Test for path traversal vulnerabilities',
            'result': self._test_path_traversal()
        })
        
        findings.append({
            'id': 'V12.3.5',
            'title': 'File Inclusion Vulnerabilities',
            'severity': 'CRITICAL',
            'test': 'Test for LFI/RFI vulnerabilities',
            'result': self._test_file_inclusion()
        })
        
        # V12.4: File Storage
        findings.append({
            'id': 'V12.4.1',
            'title': 'Uploaded File Storage Location',
            'severity': 'HIGH',
            'test': 'Verify files stored outside web root',
            'result': self._test_file_storage_location()
        })
        
        # V12.5: File Download
        findings.append({
            'id': 'V12.5.1',
            'title': 'Content-Disposition Header',
            'severity': 'LOW',
            'test': 'Check for proper Content-Disposition headers',
            'result': self._test_content_disposition()
        })
        
        findings.append({
            'id': 'V12.5.2',
            'title': 'Arbitrary File Download',
            'severity': 'HIGH',
            'test': 'Test for arbitrary file download',
            'result': self._test_arbitrary_download()
        })
        
        # V12.6: SSRF Protection
        findings.append({
            'id': 'V12.6.1',
            'title': 'Server-Side Request Forgery',
            'severity': 'HIGH',
            'test': 'Test for SSRF vulnerabilities',
            'result': self._test_ssrf()
        })
        
        return {
            'category': 'Files and Resources',
            'findings': findings,
            'score': self._calculate_score(findings)
        }
    
    def _test_api(self) -> Dict:
        """V13: API and Web Service"""
        print("\n[*] V13: Testing API Security...")
        findings = []
        
        # V13.1: Generic Web Service Security
        findings.append({
            'id': 'V13.1.1',
            'title': 'API Schema Validation',
            'severity': 'MEDIUM',
            'test': 'Verify API input validation',
            'result': self._test_api_validation()
        })
        
        findings.append({
            'id': 'V13.1.3',
            'title': 'API URL Structure',
            'severity': 'INFO',
            'test': 'Check RESTful API structure',
            'result': self._test_api_structure()
        })
        
        findings.append({
            'id': 'V13.1.4',
            'title': 'GraphQL/XML Authorization',
            'severity': 'HIGH',
            'test': 'Test API authorization controls',
            'result': self._test_api_authorization()
        })
        
        # V13.2: RESTful Web Service
        findings.append({
            'id': 'V13.2.1',
            'title': 'HTTP Verb Tampering',
            'severity': 'MEDIUM',
            'test': 'Test for HTTP method override',
            'result': self._test_http_verb_tampering()
        })
        
        findings.append({
            'id': 'V13.2.3',
            'title': 'API Rate Limiting',
            'severity': 'MEDIUM',
            'test': 'Verify API rate limiting',
            'result': self._test_api_rate_limiting()
        })
        
        findings.append({
            'id': 'V13.2.6',
            'title': 'Mass Assignment Protection',
            'severity': 'HIGH',
            'test': 'Test for mass assignment vulnerabilities',
            'result': self._test_mass_assignment()
        })
        
        # V13.3: SOAP Web Service
        findings.append({
            'id': 'V13.3.1',
            'title': 'SOAP/XML Schema Validation',
            'severity': 'HIGH',
            'test': 'Verify SOAP message validation',
            'result': self._test_soap_validation()
        })
        
        # V13.4: GraphQL
        findings.append({
            'id': 'V13.4.1',
            'title': 'GraphQL Query Depth Limiting',
            'severity': 'MEDIUM',
            'test': 'Check for GraphQL query complexity limits',
            'result': self._test_graphql_complexity()
        })
        
        findings.append({
            'id': 'V13.4.2',
            'title': 'GraphQL Introspection',
            'severity': 'LOW',
            'test': 'Check if GraphQL introspection is enabled',
            'result': self._test_graphql_introspection()
        })
        
        return {
            'category': 'API and Web Service',
            'findings': findings,
            'score': self._calculate_score(findings)
        }
    
    def _test_configuration(self) -> Dict:
        """V14: Configuration"""
        print("\n[*] V14: Testing Configuration...")
        findings = []
        
        # V14.1: Build and Deploy
        findings.append({
            'id': 'V14.1.1',
            'title': 'Build Process Security',
            'severity': 'INFO',
            'test': 'Check for secure build process',
            'result': self._test_build_security()
        })
        
        findings.append({
            'id': 'V14.1.3',
            'title': 'Dependency Security',
            'severity': 'HIGH',
            'test': 'Check for vulnerable dependencies',
            'result': self._test_dependencies()
        })
        
        # V14.2: Dependency
        findings.append({
            'id': 'V14.2.1',
            'title': 'Component Versions',
            'severity': 'MEDIUM',
            'test': 'Identify outdated components',
            'result': self._test_component_versions()
        })
        
        findings.append({
            'id': 'V14.2.6',
            'title': 'Unnecessary Features',
            'severity': 'LOW',
            'test': 'Check for unnecessary features/pages',
            'result': self._test_unnecessary_features()
        })
        
        # V14.3: Unintended Security Disclosure
        findings.append({
            'id': 'V14.3.1',
            'title': 'robots.txt Information Disclosure',
            'severity': 'INFO',
            'test': 'Check robots.txt for sensitive paths',
            'result': self._test_robots_txt()
        })
        
        findings.append({
            'id': 'V14.3.2',
            'title': 'HTTP Header Information Disclosure',
            'severity': 'LOW',
            'test': 'Check for version disclosure in headers',
            'result': self._test_header_disclosure()
        })
        
        findings.append({
            'id': 'V14.3.3',
            'title': 'Comments in Source Code',
            'severity': 'LOW',
            'test': 'Check for sensitive information in comments',
            'result': self._test_source_comments()
        })
        
        # V14.4: HTTP Security Headers
        findings.append({
            'id': 'V14.4.1',
            'title': 'Content-Security-Policy Header',
            'severity': 'MEDIUM',
            'test': 'Verify CSP header is present and secure',
            'result': self._test_csp_header()
        })
        
        findings.append({
            'id': 'V14.4.2',
            'title': 'X-Content-Type-Options Header',
            'severity': 'LOW',
            'test': 'Check for X-Content-Type-Options: nosniff',
            'result': self._test_content_type_options()
        })
        
        findings.append({
            'id': 'V14.4.3',
            'title': 'X-Frame-Options Header',
            'severity': 'MEDIUM',
            'test': 'Verify clickjacking protection',
            'result': self._test_x_frame_options()
        })
        
        findings.append({
            'id': 'V14.4.4',
            'title': 'Referrer-Policy Header',
            'severity': 'LOW',
            'test': 'Check Referrer-Policy header',
            'result': self._test_referrer_policy()
        })
        
        findings.append({
            'id': 'V14.4.5',
            'title': 'Feature-Policy/Permissions-Policy',
            'severity': 'LOW',
            'test': 'Verify feature policy is set',
            'result': self._test_feature_policy()
        })
        
        # V14.5: HTTP Request Header Validation
        findings.append({
            'id': 'V14.5.1',
            'title': 'Host Header Injection',
            'severity': 'MEDIUM',
            'test': 'Test for host header injection',
            'result': self._test_host_header_injection()
        })
        
        findings.append({
            'id': 'V14.5.3',
            'title': 'HTTP Request Smuggling',
            'severity': 'HIGH',
            'test': 'Test for HTTP request smuggling',
            'result': self._test_request_smuggling()
        })
        
        return {
            'category': 'Configuration',
            'findings': findings,
            'score': self._calculate_score(findings)
        }
    
    # =====================================================================
    # HELPER METHODS - Actual test implementations
    # =====================================================================
    
    def _check_source_exposure(self) -> Dict:
        """Check for exposed source code files"""
        exposed_files = []
        source_patterns = [
            '/static/source_code.tar.gz', '/static/source_code.zip',
            '/source.tar.gz', '/backup.zip', '/src.tar.gz',
            '/.git/HEAD', '/.git/config', '/.svn/entries',
            '/package.json', '/composer.json', '/requirements.txt'
        ]
        
        for pattern in source_patterns:
            try:
                r = self.session.get(f"{self.target_url}{pattern}", timeout=5)
                if r.status_code == 200:
                    exposed_files.append(pattern)
            except:
                pass
        
        return {
            'status': 'FAIL' if exposed_files else 'PASS',
            'details': f"Exposed files: {exposed_files}" if exposed_files else "No source code exposure detected",
            'recommendation': "Remove or restrict access to source code archives" if exposed_files else None
        }
    
    def _identify_auth_components(self) -> Dict:
        """Identify authentication mechanisms"""
        auth_endpoints = []
        patterns = ['/login', '/signin', '/auth', '/authenticate', '/api/auth', '/oauth']
        
        for pattern in patterns:
            try:
                r = self.session.get(f"{self.target_url}{pattern}", timeout=5)
                if r.status_code in [200, 302, 401]:
                    auth_endpoints.append({
                        'endpoint': pattern,
                        'status': r.status_code,
                        'method': 'Form-based' if 'form' in r.text.lower() else 'Unknown'
                    })
            except:
                pass
        
        return {
            'status': 'INFO',
            'details': f"Found {len(auth_endpoints)} authentication endpoints",
            'endpoints': auth_endpoints
        }
    
    def _detect_access_control_model(self) -> Dict:
        """Detect access control implementation"""
        # Check for common authorization patterns
        indicators = {
            'role_based': False,
            'attribute_based': False,
            'session_based': False
        }
        
        try:
            r = self.session.get(self.target_url, timeout=5)
            
            # Check cookies for session/role indicators
            for cookie in self.session.cookies:
                if 'role' in cookie.name.lower() or 'permission' in cookie.name.lower():
                    indicators['role_based'] = True
                if 'session' in cookie.name.lower():
                    indicators['session_based'] = True
        except:
            pass
        
        return {
            'status': 'INFO',
            'details': f"Access control indicators: {indicators}"
        }
    
    def _check_error_disclosure(self) -> Dict:
        """Check for verbose error messages"""
        test_urls = [
            f"{self.target_url}/nonexistent",
            f"{self.target_url}/admin/test",
            f"{self.target_url}/'",
            f"{self.target_url}/test.php",
        ]
        
        disclosures = []
        disclosure_patterns = [
            r'(flask|django|express|laravel)',
            r'(traceback|stacktrace|exception)',
            r'(sql|mysql|postgres|mongodb)',
            r'(line \d+ in)',
            r'(c:\\|/var/www|/usr|/home)',
            r'(version \d+\.\d+)',
        ]
        
        for url in test_urls:
            try:
                r = self.session.get(url, timeout=5)
                for pattern in disclosure_patterns:
                    matches = re.findall(pattern, r.text, re.IGNORECASE)
                    if matches:
                        disclosures.append({
                            'url': url,
                            'pattern': pattern,
                            'matches': matches[:3]
                        })
            except:
                pass
        
        return {
            'status': 'FAIL' if disclosures else 'PASS',
            'details': f"Found {len(disclosures)} error disclosure instances" if disclosures else "No verbose errors detected",
            'disclosures': disclosures[:5],
            'recommendation': "Implement generic error pages" if disclosures else None
        }
    
    def _check_config_exposure(self) -> Dict:
        """Check for exposed configuration files"""
        config_files = [
            '/.env', '/config.php', '/config.json', '/web.config',
            '/app.config', '/.htaccess', '/config.yml', '/.config',
            '/configuration.php', '/settings.py', '/database.yml'
        ]
        
        exposed = []
        for file in config_files:
            try:
                r = self.session.get(f"{self.target_url}{file}", timeout=5)
                if r.status_code == 200 and len(r.content) > 0:
                    exposed.append(file)
            except:
                pass
        
        return {
            'status': 'FAIL' if exposed else 'PASS',
            'details': f"Exposed config files: {exposed}" if exposed else "No exposed configuration files",
            'recommendation': "Restrict access to configuration files" if exposed else None
        }
    
    # Authentication tests
    def _test_password_policy(self) -> Dict:
        """Test password policy"""
        # This would require actual testing during registration
        return {
            'status': 'INFO',
            'details': "Manual test required: Attempt registration with weak passwords (123, password, etc.)",
            'recommendation': "Implement NIST SP 800-63B password guidelines"
        }
    
    def _test_breach_detection(self) -> Dict:
        """Check for breach database validation"""
        return {
            'status': 'INFO',
            'details': "Manual verification required: Check if Have I Been Pwned API is used",
            'recommendation': "Integrate with breach databases like HIBP"
        }
    
    def _test_anti_automation(self) -> Dict:
        """Test for anti-automation controls"""
        # Attempt multiple rapid requests
        try:
            responses = []
            for i in range(15):
                r = self.session.get(f"{self.target_url}/login", timeout=5)
                responses.append(r.status_code)
            
            # Check for rate limiting (429) or CAPTCHA
            has_rate_limit = 429 in responses or 403 in responses
            
            return {
                'status': 'PASS' if has_rate_limit else 'FAIL',
                'details': f"Rate limiting detected" if has_rate_limit else "No rate limiting detected (15 requests succeeded)",
                'recommendation': "Implement rate limiting and CAPTCHA" if not has_rate_limit else None
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not test anti-automation'}
    
    def _test_username_enumeration(self) -> Dict:
        """Test for username enumeration"""
        try:
            # Test with likely invalid username
            r1 = self.session.post(f"{self.target_url}/login",
                                   data={'username': 'nonexistentuser99999', 'password': 'test'},
                                   timeout=5)
            
            # Test with common username
            r2 = self.session.post(f"{self.target_url}/login",
                                   data={'username': 'admin', 'password': 'test'},
                                   timeout=5)
            
            # Check if responses differ
            enumerable = (r1.text != r2.text) or (r1.status_code != r2.status_code)
            
            return {
                'status': 'FAIL' if enumerable else 'PASS',
                'details': "Username enumeration possible via response differences" if enumerable else "No username enumeration detected",
                'recommendation': "Use generic error messages for login failures" if enumerable else None
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not test username enumeration'}
    
    def _test_default_credentials(self) -> Dict:
        """Test for default credentials"""
        default_creds = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
            ('root', 'root'), ('test', 'test'), ('user', 'user')
        ]
        
        successful = []
        for username, password in default_creds:
            try:
                r = self.session.post(f"{self.target_url}/login",
                                     data={'username': username, 'password': password},
                                     timeout=5, allow_redirects=False)
                
                if r.status_code in [200, 302] and 'invalid' not in r.text.lower():
                    successful.append((username, password))
            except:
                pass
        
        return {
            'status': 'FAIL' if successful else 'PASS',
            'details': f"Default credentials work: {successful}" if successful else "No default credentials accepted",
            'recommendation': "Force password change on first login" if successful else None
        }
    
    def _test_password_reset(self) -> Dict:
        """Test password reset mechanism"""
        try:
            r = self.session.get(f"{self.target_url}/reset", timeout=5)
            if r.status_code == 404:
                return {'status': 'INFO', 'details': 'No password reset endpoint found'}
            
            # Check for common issues
            issues = []
            if 'token' in r.text.lower():
                issues.append('Uses token-based reset (GOOD)')
            if 'email' not in r.text.lower():
                issues.append('No email verification (BAD)')
            
            return {
                'status': 'INFO',
                'details': f"Password reset found: {', '.join(issues)}",
                'recommendation': "Ensure reset tokens are cryptographically random and expire"
            }
        except:
            return {'status': 'INFO', 'details': 'No password reset endpoint found'}
    
    def _test_otp_implementation(self) -> Dict:
        """Check for OTP/2FA"""
        return {
            'status': 'INFO',
            'details': "Manual check required: Look for 2FA/MFA options in user settings",
            'recommendation': "Implement multi-factor authentication"
        }
    
    def _test_otp_reuse(self) -> Dict:
        """Test if OTPs can be reused"""
        return {
            'status': 'INFO',
            'details': "Manual test required if OTP is implemented",
            'recommendation': "Ensure OTPs are single-use only"
        }
    
    def _test_api_auth(self) -> Dict:
        """Test API authentication"""
        try:
            r = self.session.get(f"{self.target_url}/api", timeout=5)
            
            if r.status_code == 404:
                return {'status': 'INFO', 'details': 'No API endpoints detected'}
            
            # Check for authentication requirement
            requires_auth = r.status_code in [401, 403]
            
            return {
                'status': 'PASS' if requires_auth else 'FAIL',
                'details': "API requires authentication" if requires_auth else "API accessible without authentication",
                'recommendation': "Implement API key or OAuth authentication" if not requires_auth else None
            }
        except:
            return {'status': 'INFO', 'details': 'No API endpoints detected'}
    
    # Session Management tests
    def _test_session_in_url(self) -> Dict:
        """Check if session tokens are in URLs"""
        try:
            r = self.session.get(self.target_url, timeout=5)
            
            # Check for session-like parameters in URL
            url_params = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query)
            session_in_url = any(k.lower() in ['session', 'sessionid', 'sessid', 'token'] for k in url_params.keys())
            
            return {
                'status': 'FAIL' if session_in_url else 'PASS',
                'details': "Session token found in URL" if session_in_url else "No session tokens in URLs",
                'recommendation': "Use cookies or headers for session management" if session_in_url else None
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not test session in URL'}
    
    def _test_session_randomness(self) -> Dict:
        """Test session token randomness"""
        sessions = []
        try:
            for i in range(3):
                temp_session = requests.Session()
                r = temp_session.get(f"{self.target_url}/login", timeout=5)
                
                for cookie in temp_session.cookies:
                    if 'session' in cookie.name.lower():
                        sessions.append(cookie.value)
            
            if len(sessions) < 2:
                return {'status': 'INFO', 'details': 'Could not collect session tokens'}
            
            # Check if tokens are different and sufficiently long
            all_different = len(set(sessions)) == len(sessions)
            sufficient_length = all(len(s) >= 32 for s in sessions)
            
            return {
                'status': 'PASS' if (all_different and sufficient_length) else 'FAIL',
                'details': f"Session randomness: Different={all_different}, Length>32={sufficient_length}",
                'recommendation': "Use cryptographically random session tokens (128+ bits)" if not (all_different and sufficient_length) else None
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not test session randomness'}
    
    def _test_session_fixation(self) -> Dict:
        """Test for session fixation"""
        try:
            # Get session before login
            s1 = requests.Session()
            r1 = s1.get(f"{self.target_url}/login", timeout=5)
            pre_login_session = s1.cookies.get('session', '')
            
            # Would need to actually login to test properly
            return {
                'status': 'INFO',
                'details': "Manual test required: Check if session ID changes after login",
                'recommendation': "Regenerate session ID after authentication"
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not test session fixation'}
    
    def _test_logout(self) -> Dict:
        """Test logout functionality"""
        try:
            r = self.session.get(f"{self.target_url}/logout", timeout=5)
            
            if r.status_code == 404:
                return {'status': 'FAIL', 'details': 'No logout endpoint found', 'recommendation': 'Implement proper logout functionality'}
            
            # Check if cookies were cleared
            cookies_cleared = len(self.session.cookies) == 0
            
            return {
                'status': 'PASS' if cookies_cleared else 'WARN',
                'details': "Logout clears session" if cookies_cleared else "Logout does not clear all cookies",
                'recommendation': "Ensure logout invalidates all session tokens" if not cookies_cleared else None
            }
        except:
            return {'status': 'INFO', 'details': 'Could not test logout'}
    
    def _test_session_timeout(self) -> Dict:
        """Check for session timeout"""
        return {
            'status': 'INFO',
            'details': "Manual test required: Check if session expires after inactivity",
            'recommendation': "Implement 15-30 minute idle timeout"
        }
    
    def _test_cookie_flags(self) -> Dict:
        """Test cookie security flags"""
        try:
            r = self.session.get(self.target_url, timeout=5)
            
            issues = []
            for cookie in self.session.cookies:
                if 'session' in cookie.name.lower() or 'auth' in cookie.name.lower():
                    if not cookie.secure:
                        issues.append(f"{cookie.name}: Missing Secure flag")
                    if not cookie.has_nonstandard_attr('HttpOnly'):
                        issues.append(f"{cookie.name}: Missing HttpOnly flag")
                    if not cookie.has_nonstandard_attr('SameSite'):
                        issues.append(f"{cookie.name}: Missing SameSite flag")
            
            return {
                'status': 'FAIL' if issues else 'PASS',
                'details': '; '.join(issues) if issues else "All security flags present",
                'recommendation': "Set Secure, HttpOnly, and SameSite=Strict flags" if issues else None
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not test cookie flags'}
    
    def _test_cookie_scope(self) -> Dict:
        """Test cookie scope"""
        try:
            cookies = []
            for cookie in self.session.cookies:
                cookies.append({
                    'name': cookie.name,
                    'domain': cookie.domain,
                    'path': cookie.path
                })
            
            # Check for overly broad scope
            issues = []
            for cookie in cookies:
                if cookie['path'] == '/':
                    issues.append(f"{cookie['name']}: Broad path scope")
            
            return {
                'status': 'WARN' if issues else 'PASS',
                'details': '; '.join(issues) if issues else "Cookie scope appropriate",
                'recommendation': "Use specific paths for cookies" if issues else None
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not test cookie scope'}
    
    def _test_jwt_security(self) -> Dict:
        """Test JWT implementation"""
        # Check headers and cookies for JWT
        jwt_found = False
        jwt_issues = []
        
        try:
            r = self.session.get(self.target_url, timeout=5)
            
            # Check Authorization header
            if 'authorization' in r.request.headers:
                token = r.request.headers['authorization']
                if token.startswith('Bearer '):
                    jwt_found = True
                    # Basic JWT security checks
                    if token.count('.') != 2:
                        jwt_issues.append("Invalid JWT format")
            
            # Check cookies for JWT
            for cookie in self.session.cookies:
                if '.' in cookie.value and cookie.value.count('.') == 2:
                    jwt_found = True
            
            if not jwt_found:
                return {'status': 'INFO', 'details': 'No JWT implementation detected'}
            
            return {
                'status': 'WARN' if jwt_issues else 'INFO',
                'details': f"JWT detected. Issues: {jwt_issues}" if jwt_issues else "JWT detected",
                'recommendation': "Verify JWT signature algorithm is not 'none', use RS256 or ES256"
            }
        except:
            return {'status': 'INFO', 'details': 'No JWT implementation detected'}
    
    # Additional test method stubs (implement as needed)
    def _test_default_deny(self) -> Dict:
        return {'status': 'INFO', 'details': 'Manual code review required'}
    
    def _test_idor(self) -> Dict:
        return {'status': 'INFO', 'details': 'Manual testing required with authenticated users'}
    
    def _test_sensitive_operations(self) -> Dict:
        return {'status': 'INFO', 'details': 'Manual testing required'}
    
    def _test_admin_access(self) -> Dict:
        """Check admin interface access"""
        admin_paths = ['/admin', '/administrator', '/manage', '/dashboard', '/console', '/panel']
        accessible = []
        
        for path in admin_paths:
            try:
                r = self.session.get(f"{self.target_url}{path}", timeout=5)
                if r.status_code == 200:
                    accessible.append(path)
            except:
                pass
        
        return {
            'status': 'FAIL' if accessible else 'PASS',
            'details': f"Admin interfaces found: {accessible}" if accessible else "No admin interfaces accessible",
            'recommendation': "Implement strong authentication for admin interfaces" if accessible else None
        }
    
    def _test_directory_browsing(self) -> Dict:
        """Test for directory listing"""
        test_dirs = ['/uploads/', '/files/', '/images/', '/static/', '/assets/']
        browsable = []
        
        for dir_path in test_dirs:
            try:
                r = self.session.get(f"{self.target_url}{dir_path}", timeout=5)
                if 'Index of' in r.text or 'Directory listing' in r.text:
                    browsable.append(dir_path)
            except:
                pass
        
        return {
            'status': 'FAIL' if browsable else 'PASS',
            'details': f"Browsable directories: {browsable}" if browsable else "No directory browsing",
            'recommendation': "Disable directory listing" if browsable else None
        }
    
    # Validation tests
    def _test_input_validation(self) -> Dict:
        return {'status': 'INFO', 'details': 'Manual testing required with various input types'}
    
    def _test_structured_data(self) -> Dict:
        return {'status': 'INFO', 'details': 'Test JSON/XML input validation manually'}
    
    def _test_xss(self) -> Dict:
        """Test for XSS vulnerabilities"""
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "javascript:alert(1)",
            '<img src=x onerror=alert(1)>'
        ]
        
        vulnerabilities = []
        
        # Test common input points
        test_params = ['q', 'search', 'name', 'comment', 'message']
        
        for param in test_params:
            for payload in xss_payloads:
                try:
                    r = self.session.get(f"{self.target_url}/?{param}={urllib.parse.quote(payload)}", timeout=5)
                    if payload in r.text and '<script' in r.text:
                        vulnerabilities.append(f"{param}: {payload}")
                        break
                except:
                    pass
        
        return {
            'status': 'FAIL' if vulnerabilities else 'PASS',
            'details': f"XSS vulnerabilities: {vulnerabilities[:3]}" if vulnerabilities else "No XSS detected",
            'recommendation': "Implement context-aware output encoding" if vulnerabilities else None
        }
    
    def _test_sql_injection(self) -> Dict:
        """Test for SQL injection"""
        sqli_payloads = ["'", "' OR '1'='1", "1' AND '1'='1", "'; DROP TABLE users--"]
        
        vulnerabilities = []
        test_params = ['id', 'user', 'search', 'q']
        
        for param in test_params:
            for payload in sqli_payloads:
                try:
                    r = self.session.get(f"{self.target_url}/?{param}={urllib.parse.quote(payload)}", timeout=5)
                    
                    # Check for SQL error messages
                    sql_errors = ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle', 'syntax error', 'unexpected']
                    if any(err in r.text.lower() for err in sql_errors):
                        vulnerabilities.append(f"{param}: {payload}")
                        break
                except:
                    pass
        
        return {
            'status': 'FAIL' if vulnerabilities else 'PASS',
            'details': f"Potential SQLi: {vulnerabilities[:3]}" if vulnerabilities else "No SQL injection detected",
            'recommendation': "Use parameterized queries/prepared statements" if vulnerabilities else None
        }
    
    def _test_output_encoding(self) -> Dict:
        return {'status': 'INFO', 'details': 'Manual review of output encoding required'}
    
    def _test_ssti(self) -> Dict:
        """Test for Server-Side Template Injection"""
        ssti_payloads = [
            '{{7*7}}',
            '${7*7}',
            '<%= 7*7 %>',
            '#{7*7}'
        ]
        
        vulnerabilities = []
        
        for payload in ssti_payloads:
            try:
                r = self.session.get(f"{self.target_url}/?test={urllib.parse.quote(payload)}", timeout=5)
                if '49' in r.text:  # 7*7=49
                    vulnerabilities.append(payload)
            except:
                pass
        
        return {
            'status': 'FAIL' if vulnerabilities else 'PASS',
            'details': f"SSTI detected: {vulnerabilities}" if vulnerabilities else "No SSTI detected",
            'recommendation': "Use safe template rendering, avoid user input in templates" if vulnerabilities else None
        }
    
    def _test_xxe(self) -> Dict:
        """Test for XXE vulnerabilities"""
        return {
            'status': 'INFO',
            'details': 'XXE testing requires XML input endpoints',
            'recommendation': "Disable external entity processing in XML parsers"
        }
    
    def _test_command_injection(self) -> Dict:
        """Test for command injection"""
        cmd_payloads = ['; ls', '| whoami', '`id`', '$(whoami)']
        
        vulnerabilities = []
        
        for payload in cmd_payloads:
            try:
                r = self.session.get(f"{self.target_url}/?cmd={urllib.parse.quote(payload)}", timeout=5)
                
                # Check for command output indicators
                if any(indicator in r.text.lower() for indicator in ['uid=', 'gid=', 'root', 'www-data']):
                    vulnerabilities.append(payload)
            except:
                pass
        
        return {
            'status': 'FAIL' if vulnerabilities else 'PASS',
            'details': f"Command injection detected: {vulnerabilities}" if vulnerabilities else "No command injection detected",
            'recommendation': "Avoid system calls with user input, use safe APIs" if vulnerabilities else None
        }
    
    def _test_deserialization(self) -> Dict:
        return {'status': 'INFO', 'details': 'Manual testing required for deserialization'}
    
    # Cryptography tests
    def _test_weak_crypto(self) -> Dict:
        """Check for weak cryptographic algorithms"""
        # This would typically be found through code review
        return {
            'status': 'INFO',
            'details': 'Code review required to identify cryptographic algorithms',
            'recommendation': "Use AES-256-GCM, RSA-2048+, SHA-256+"
        }
    
    def _test_random_generation(self) -> Dict:
        return {'status': 'INFO', 'details': 'Code review required'}
    
    def _test_hardcoded_secrets(self) -> Dict:
        """Check for hardcoded secrets (from source if available)"""
        return {
            'status': 'INFO',
            'details': 'Source code review required for hardcoded secrets',
            'recommendation': "Use environment variables or secret management systems"
        }
    
    def _test_key_rotation(self) -> Dict:
        return {'status': 'INFO', 'details': 'Operational review required'}
    
    # Error handling tests
    def _test_security_logging(self) -> Dict:
        return {'status': 'INFO', 'details': 'Log review required'}
    
    def _test_log_injection(self) -> Dict:
        return {'status': 'INFO', 'details': 'Manual testing required'}
    
    def _test_log_protection(self) -> Dict:
        """Check if log files are accessible"""
        log_files = ['/logs/app.log', '/var/log/application.log', '/log.txt', '/debug.log']
        accessible = []
        
        for log in log_files:
            try:
                r = self.session.get(f"{self.target_url}{log}", timeout=5)
                if r.status_code == 200:
                    accessible.append(log)
            except:
                pass
        
        return {
            'status': 'FAIL' if accessible else 'PASS',
            'details': f"Accessible logs: {accessible}" if accessible else "No log files accessible",
            'recommendation': "Restrict access to log files" if accessible else None
        }
    
    def _test_error_messages(self) -> Dict:
        """Test error message verbosity"""
        try:
            r = self.session.get(f"{self.target_url}/nonexistent123456", timeout=5)
            
            # Check for technical details
            technical_details = ['traceback', 'stack trace', 'line', 'file', 'exception', 'debug']
            has_details = any(detail in r.text.lower() for detail in technical_details)
            
            return {
                'status': 'FAIL' if has_details else 'PASS',
                'details': "Error messages contain technical details" if has_details else "Generic error messages",
                'recommendation': "Use generic error messages for users" if has_details else None
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not test error messages'}
    
    def _test_debug_mode(self) -> Dict:
        """Check if debug mode is enabled"""
        try:
            r = self.session.get(self.target_url, timeout=5)
            
            # Check for debug indicators
            debug_indicators = ['debug=true', 'debug mode', 'flask debug', 'django debug', 'development mode']
            debug_enabled = any(indicator in r.text.lower() for indicator in debug_indicators)
            
            # Check headers
            debug_headers = ['x-debug', 'x-powered-by']
            has_debug_headers = any(header in [h.lower() for h in r.headers.keys()] for header in debug_headers)
            
            return {
                'status': 'FAIL' if (debug_enabled or has_debug_headers) else 'PASS',
                'details': "Debug mode appears to be enabled" if (debug_enabled or has_debug_headers) else "No debug mode detected",
                'recommendation': "Disable debug mode in production" if (debug_enabled or has_debug_headers) else None
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not test debug mode'}
    
    # Data protection tests
    def _test_data_at_rest(self) -> Dict:
        return {'status': 'INFO', 'details': 'Infrastructure review required'}
    
    def _test_client_storage(self) -> Dict:
        """Check for sensitive data in client storage"""
        try:
            r = self.session.get(self.target_url, timeout=5)
            
            # Check for localStorage/sessionStorage usage with sensitive data
            storage_usage = 'localstorage' in r.text.lower() or 'sessionstorage' in r.text.lower()
            
            # Check for sensitive keywords near storage calls
            sensitive_keywords = ['password', 'token', 'secret', 'key', 'ssn', 'credit']
            sensitive_in_storage = storage_usage and any(kw in r.text.lower() for kw in sensitive_keywords)
            
            return {
                'status': 'FAIL' if sensitive_in_storage else 'PASS',
                'details': "Potentially sensitive data in client storage" if sensitive_in_storage else "No obvious sensitive data in client storage",
                'recommendation': "Avoid storing sensitive data in localStorage/sessionStorage" if sensitive_in_storage else None
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not test client storage'}
    
    def _test_autocomplete(self) -> Dict:
        """Check autocomplete on sensitive fields"""
        try:
            r = self.session.get(f"{self.target_url}/login", timeout=5)
            
            # Check for password fields with autocomplete
            password_autocomplete = '<input type="password"' in r.text and 'autocomplete="off"' not in r.text
            
            return {
                'status': 'FAIL' if password_autocomplete else 'PASS',
                'details': "Password fields allow autocomplete" if password_autocomplete else "Autocomplete disabled on sensitive fields",
                'recommendation': "Add autocomplete='off' to sensitive input fields" if password_autocomplete else None
            }
        except:
            return {'status': 'INFO', 'details': 'Could not test autocomplete'}
    
    def _test_pii_handling(self) -> Dict:
        return {'status': 'INFO', 'details': 'Manual review of PII handling required'}
    
    def _test_memory_data(self) -> Dict:
        return {'status': 'INFO', 'details': 'Code review required'}
    
    # Communication tests
    def _test_tls_usage(self) -> Dict:
        """Check if TLS is enforced"""
        is_https = self.target_url.startswith('https://')
        
        if not is_https:
            # Try HTTPS version
            try:
                https_url = self.target_url.replace('http://', 'https://')
                r = self.session.get(https_url, timeout=5, verify=False)
                https_available = r.status_code < 400
            except:
                https_available = False
            
            return {
                'status': 'FAIL',
                'details': f"Site uses HTTP. HTTPS {'available' if https_available else 'not available'}",
                'recommendation': "Enforce HTTPS for all connections"
            }
        
        return {'status': 'PASS', 'details': 'TLS in use'}
    
    def _test_tls_config(self) -> Dict:
        """Check TLS configuration"""
        if not self.target_url.startswith('https://'):
            return {'status': 'SKIP', 'details': 'Not using HTTPS'}
        
        return {
            'status': 'INFO',
            'details': 'Use SSL Labs or testssl.sh for comprehensive TLS testing',
            'recommendation': "Ensure TLS 1.2+ only, strong cipher suites"
        }
    
    def _test_certificate(self) -> Dict:
        """Check TLS certificate"""
        if not self.target_url.startswith('https://'):
            return {'status': 'SKIP', 'details': 'Not using HTTPS'}
        
        try:
            r = self.session.get(self.target_url, timeout=5, verify=True)
            return {'status': 'PASS', 'details': 'Valid TLS certificate'}
        except requests.exceptions.SSLError:
            return {
                'status': 'FAIL',
                'details': 'Invalid or self-signed certificate',
                'recommendation': 'Use a valid certificate from trusted CA'
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not verify certificate'}
    
    def _test_trusted_cert(self) -> Dict:
        """Check for trusted certificate"""
        return self._test_certificate()
    
    def _test_hsts(self) -> Dict:
        """Check for HSTS header"""
        if not self.target_url.startswith('https://'):
            return {'status': 'SKIP', 'details': 'Not using HTTPS'}
        
        try:
            r = self.session.get(self.target_url, timeout=5)
            hsts = r.headers.get('Strict-Transport-Security', '')
            
            if not hsts:
                return {
                    'status': 'FAIL',
                    'details': 'HSTS header missing',
                    'recommendation': 'Add Strict-Transport-Security header with max-age >= 31536000'
                }
            
            # Check max-age
            max_age = re.search(r'max-age=(\d+)', hsts)
            if max_age and int(max_age.group(1)) >= 31536000:
                return {'status': 'PASS', 'details': f'HSTS enabled: {hsts}'}
            else:
                return {
                    'status': 'WARN',
                    'details': f'HSTS max-age too short: {hsts}',
                    'recommendation': 'Set max-age to at least 31536000 (1 year)'
                }
        except:
            return {'status': 'ERROR', 'details': 'Could not check HSTS'}
    
    # Malicious code tests
    def _test_git_exposure(self) -> Dict:
        """Check for exposed .git directory"""
        git_files = ['/.git/HEAD', '/.git/config', '/.git/index']
        exposed = []
        
        for file in git_files:
            try:
                r = self.session.get(f"{self.target_url}{file}", timeout=5)
                if r.status_code == 200:
                    exposed.append(file)
            except:
                pass
        
        return {
            'status': 'FAIL' if exposed else 'PASS',
            'details': f"Exposed .git files: {exposed}" if exposed else "No .git exposure",
            'recommendation': "Remove .git directory from production" if exposed else None
        }
    
    def _test_suspicious_code(self) -> Dict:
        return {'status': 'INFO', 'details': 'Code review required for malicious code detection'}
    
    def _test_subresource_integrity(self) -> Dict:
        """Check for Subresource Integrity"""
        try:
            r = self.session.get(self.target_url, timeout=5)
            
            # Check for external scripts/styles
            external_resources = re.findall(r'<(?:script|link)[^>]+(?:src|href)=["\']https?://[^"\']+["\'][^>]*>', r.text)
            
            # Check for SRI
            sri_count = sum(1 for resource in external_resources if 'integrity=' in resource)
            
            if not external_resources:
                return {'status': 'INFO', 'details': 'No external resources found'}
            
            sri_percentage = (sri_count / len(external_resources)) * 100 if external_resources else 0
            
            return {
                'status': 'PASS' if sri_percentage > 80 else 'FAIL',
                'details': f"SRI on {sri_count}/{len(external_resources)} external resources ({sri_percentage:.0f}%)",
                'recommendation': "Add integrity attributes to all external resources" if sri_percentage < 100 else None
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not check SRI'}
    
    def _test_client_integrity(self) -> Dict:
        return {'status': 'INFO', 'details': 'Manual review required'}
    
    # Business logic tests
    def _test_business_flow(self) -> Dict:
        return {'status': 'INFO', 'details': 'Manual business logic testing required'}
    
    def _test_transaction_order(self) -> Dict:
        return {'status': 'INFO', 'details': 'Manual testing of transaction flows required'}
    
    def _test_rate_limiting(self) -> Dict:
        """Test for rate limiting"""
        try:
            responses = []
            for i in range(20):
                r = self.session.get(self.target_url, timeout=5)
                responses.append(r.status_code)
            
            rate_limited = 429 in responses
            
            return {
                'status': 'PASS' if rate_limited else 'FAIL',
                'details': "Rate limiting detected" if rate_limited else "No rate limiting (20 rapid requests succeeded)",
                'recommendation': "Implement rate limiting to prevent abuse" if not rate_limited else None
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not test rate limiting'}
    
    def _test_replay_protection(self) -> Dict:
        return {'status': 'INFO', 'details': 'Manual testing required'}
    
    def _test_race_conditions(self) -> Dict:
        return {'status': 'INFO', 'details': 'Manual testing required with concurrent requests'}
    
    # File handling tests
    def _test_file_upload_validation(self) -> Dict:
        return {'status': 'INFO', 'details': 'Manual file upload testing required'}
    
    def _test_file_size_limits(self) -> Dict:
        return {'status': 'INFO', 'details': 'Manual testing with large files required'}
    
    def _test_file_content_validation(self) -> Dict:
        return {'status': 'INFO', 'details': 'Manual testing with malicious files required'}
    
    def _test_file_execution(self) -> Dict:
        return {'status': 'INFO', 'details': 'Manual testing required'}
    
    def _test_path_traversal(self) -> Dict:
        """Test for path traversal"""
        traversal_payloads = ['../../../etc/passwd', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', '....//....//....//etc/passwd']
        
        vulnerabilities = []
        
        for payload in traversal_payloads:
            try:
                r = self.session.get(f"{self.target_url}/file?path={urllib.parse.quote(payload)}", timeout=5)
                
                # Check for file content indicators
                if 'root:' in r.text or '[boot loader]' in r.text:
                    vulnerabilities.append(payload)
            except:
                pass
        
        return {
            'status': 'FAIL' if vulnerabilities else 'PASS',
            'details': f"Path traversal detected: {vulnerabilities}" if vulnerabilities else "No path traversal detected",
            'recommendation': "Validate and sanitize file paths" if vulnerabilities else None
        }
    
    def _test_file_inclusion(self) -> Dict:
        """Test for LFI/RFI"""
        lfi_payloads = ['../../../../../../etc/passwd', 'php://filter/convert.base64-encode/resource=index.php']
        
        vulnerabilities = []
        
        for payload in lfi_payloads:
            try:
                r = self.session.get(f"{self.target_url}/?page={urllib.parse.quote(payload)}", timeout=5)
                
                if 'root:' in r.text or 'PD9waHA' in r.text:  # base64 of <?php
                    vulnerabilities.append(payload)
            except:
                pass
        
        return {
            'status': 'FAIL' if vulnerabilities else 'PASS',
            'details': f"File inclusion detected: {vulnerabilities}" if vulnerabilities else "No file inclusion detected",
            'recommendation': "Use whitelisting for file includes" if vulnerabilities else None
        }
    
    def _test_file_storage_location(self) -> Dict:
        return {'status': 'INFO', 'details': 'Infrastructure review required'}
    
    def _test_content_disposition(self) -> Dict:
        """Check Content-Disposition headers"""
        try:
            # Try to find download endpoints
            download_endpoints = ['/download', '/file', '/export', '/attachment']
            
            for endpoint in download_endpoints:
                r = self.session.get(f"{self.target_url}{endpoint}", timeout=5)
                if r.status_code == 200:
                    cd = r.headers.get('Content-Disposition', '')
                    if not cd:
                        return {
                            'status': 'FAIL',
                            'details': 'Missing Content-Disposition header on download endpoint',
                            'recommendation': 'Add Content-Disposition: attachment header for downloads'
                        }
            
            return {'status': 'INFO', 'details': 'No download endpoints found to test'}
        except:
            return {'status': 'ERROR', 'details': 'Could not test Content-Disposition'}
    
    def _test_arbitrary_download(self) -> Dict:
        """Test for arbitrary file download"""
        test_files = ['../../../etc/passwd', '../../database.db', '../config.php']
        
        vulnerabilities = []
        
        for file in test_files:
            try:
                r = self.session.get(f"{self.target_url}/download?file={urllib.parse.quote(file)}", timeout=5)
                if r.status_code == 200 and len(r.content) > 0:
                    vulnerabilities.append(file)
            except:
                pass
        
        return {
            'status': 'FAIL' if vulnerabilities else 'PASS',
            'details': f"Arbitrary download possible: {vulnerabilities}" if vulnerabilities else "No arbitrary download detected",
            'recommendation': "Validate file paths against whitelist" if vulnerabilities else None
        }
    
    def _test_ssrf(self) -> Dict:
        """Test for SSRF vulnerabilities"""
        ssrf_payloads = [
            'http://localhost',
            'http://127.0.0.1',
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'file:///etc/passwd'
        ]
        
        vulnerabilities = []
        
        # Common SSRF parameter names
        params = ['url', 'uri', 'path', 'continue', 'dest', 'redirect', 'return']
        
        for param in params:
            for payload in ssrf_payloads:
                try:
                    r = self.session.get(f"{self.target_url}/?{param}={urllib.parse.quote(payload)}", timeout=5)
                    
                    # Check for successful SSRF indicators
                    if r.status_code == 200 and ('root:' in r.text or 'localhost' in r.text or 'ami-' in r.text):
                        vulnerabilities.append(f"{param}={payload}")
                        break
                except:
                    pass
        
        return {
            'status': 'FAIL' if vulnerabilities else 'PASS',
            'details': f"SSRF detected: {vulnerabilities}" if vulnerabilities else "No SSRF detected",
            'recommendation': "Validate and whitelist allowed URLs/IPs" if vulnerabilities else None
        }
    
    # API tests
    def _test_api_validation(self) -> Dict:
        return {'status': 'INFO', 'details': 'API testing requires API documentation'}
    
    def _test_api_structure(self) -> Dict:
        return {'status': 'INFO', 'details': 'API structure analysis requires endpoint discovery'}
    
    def _test_api_authorization(self) -> Dict:
        return {'status': 'INFO', 'details': 'API authorization testing requires authenticated access'}
    
    def _test_http_verb_tampering(self) -> Dict:
        """Test for HTTP verb tampering"""
        try:
            # Try different HTTP methods
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
            responses = {}
            
            for method in methods:
                r = self.session.request(method, f"{self.target_url}/admin", timeout=5)
                responses[method] = r.status_code
            
            # Check if different methods give different access
            access_methods = [m for m, status in responses.items() if status == 200]
            
            return {
                'status': 'WARN' if len(access_methods) > 2 else 'PASS',
                'details': f"Methods allowed: {access_methods}",
                'recommendation': "Implement proper method-based access control" if len(access_methods) > 2 else None
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not test HTTP verb tampering'}
    
    def _test_api_rate_limiting(self) -> Dict:
        return self._test_rate_limiting()
    
    def _test_mass_assignment(self) -> Dict:
        return {'status': 'INFO', 'details': 'Manual testing required with API documentation'}
    
    def _test_soap_validation(self) -> Dict:
        return {'status': 'INFO', 'details': 'SOAP testing requires SOAP endpoint'}
    
    def _test_graphql_complexity(self) -> Dict:
        """Check for GraphQL query complexity limits"""
        try:
            # Try to access GraphQL endpoint
            r = self.session.post(f"{self.target_url}/graphql", 
                                 json={'query': '{__schema{types{name}}}'}, 
                                 timeout=5)
            
            if r.status_code == 404:
                return {'status': 'INFO', 'details': 'No GraphQL endpoint detected'}
            
            # If found, test complexity
            deep_query = '{' + 'a{' * 50 + 'name' + '}' * 50 + '}'
            r2 = self.session.post(f"{self.target_url}/graphql",
                                  json={'query': deep_query},
                                  timeout=5)
            
            complexity_limited = r2.status_code == 400 or 'complexity' in r2.text.lower()
            
            return {
                'status': 'PASS' if complexity_limited else 'FAIL',
                'details': "Query complexity limits in place" if complexity_limited else "No query complexity limits",
                'recommendation': "Implement query depth and complexity limits" if not complexity_limited else None
            }
        except:
            return {'status': 'INFO', 'details': 'No GraphQL endpoint detected'}
    
    def _test_graphql_introspection(self) -> Dict:
        """Check if GraphQL introspection is enabled"""
        try:
            r = self.session.post(f"{self.target_url}/graphql",
                                 json={'query': '{__schema{types{name}}}'},
                                 timeout=5)
            
            if r.status_code == 404:
                return {'status': 'INFO', 'details': 'No GraphQL endpoint detected'}
            
            introspection_enabled = r.status_code == 200 and '__schema' in r.text
            
            return {
                'status': 'FAIL' if introspection_enabled else 'PASS',
                'details': "GraphQL introspection enabled" if introspection_enabled else "GraphQL introspection disabled",
                'recommendation': "Disable introspection in production" if introspection_enabled else None
            }
        except:
            return {'status': 'INFO', 'details': 'No GraphQL endpoint detected'}
    
    # Configuration tests
    def _test_build_security(self) -> Dict:
        return {'status': 'INFO', 'details': 'DevOps review required'}
    
    def _test_dependencies(self) -> Dict:
        """Check for vulnerable dependencies"""
        # Look for package files
        package_files = ['/package.json', '/composer.json', '/requirements.txt', '/Gemfile']
        found_packages = []
        
        for file in package_files:
            try:
                r = self.session.get(f"{self.target_url}{file}", timeout=5)
                if r.status_code == 200:
                    found_packages.append(file)
            except:
                pass
        
        return {
            'status': 'WARN' if found_packages else 'INFO',
            'details': f"Package files exposed: {found_packages}" if found_packages else "No package files found",
            'recommendation': "Use dependency scanning tools (Snyk, Dependabot)" if found_packages else "Regularly update dependencies"
        }
    
    def _test_component_versions(self) -> Dict:
        """Detect component versions"""
        try:
            r = self.session.get(self.target_url, timeout=5)
            
            versions = []
            
            # Check headers
            server = r.headers.get('Server', '')
            if server:
                versions.append(f"Server: {server}")
            
            powered_by = r.headers.get('X-Powered-By', '')
            if powered_by:
                versions.append(f"Powered-By: {powered_by}")
            
            # Check HTML for framework indicators
            frameworks = {
                'WordPress': r'wp-content|wp-includes',
                'Drupal': r'/sites/default|drupal',
                'Joomla': r'/components/com_',
                'jQuery': r'jquery[/-](\d+\.\d+\.\d+)',
                'Bootstrap': r'bootstrap[/-](\d+\.\d+\.\d+)',
            }
            
            for framework, pattern in frameworks.items():
                matches = re.findall(pattern, r.text, re.IGNORECASE)
                if matches:
                    versions.append(f"{framework}: detected")
            
            return {
                'status': 'INFO',
                'details': f"Components detected: {versions}" if versions else "No version information disclosed",
                'recommendation': "Keep all components updated"
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not detect components'}
    
    def _test_unnecessary_features(self) -> Dict:
        """Check for unnecessary features"""
        unnecessary = []
        features = ['/phpinfo.php', '/test.php', '/info.php', '/debug', '/test', '/demo']
        
        for feature in features:
            try:
                r = self.session.get(f"{self.target_url}{feature}", timeout=5)
                if r.status_code == 200:
                    unnecessary.append(feature)
            except:
                pass
        
        return {
            'status': 'FAIL' if unnecessary else 'PASS',
            'details': f"Unnecessary features: {unnecessary}" if unnecessary else "No unnecessary features detected",
            'recommendation': "Remove test/debug pages from production" if unnecessary else None
        }
    
    def _test_robots_txt(self) -> Dict:
        """Check robots.txt for sensitive paths"""
        try:
            r = self.session.get(f"{self.target_url}/robots.txt", timeout=5)
            
            if r.status_code != 200:
                return {'status': 'INFO', 'details': 'No robots.txt found'}
            
            # Look for sensitive paths
            sensitive_patterns = ['/admin', '/backup', '/config', '/db', '/sql', '/private']
            sensitive_found = []
            
            for pattern in sensitive_patterns:
                if pattern in r.text.lower():
                    sensitive_found.append(pattern)
            
            return {
                'status': 'WARN' if sensitive_found else 'PASS',
                'details': f"Sensitive paths in robots.txt: {sensitive_found}" if sensitive_found else "robots.txt looks safe",
                'recommendation': "Don't rely on robots.txt for security" if sensitive_found else None
            }
        except:
            return {'status': 'INFO', 'details': 'No robots.txt found'}
    
    def _test_header_disclosure(self) -> Dict:
        """Check for version disclosure in headers"""
        try:
            r = self.session.get(self.target_url, timeout=5)
            
            disclosures = []
            
            # Check common headers
            version_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
            
            for header in version_headers:
                value = r.headers.get(header, '')
                if value and any(char.isdigit() for char in value):
                    disclosures.append(f"{header}: {value}")
            
            return {
                'status': 'WARN' if disclosures else 'PASS',
                'details': f"Version disclosures: {disclosures}" if disclosures else "No version disclosure in headers",
                'recommendation': "Remove or genericize version information" if disclosures else None
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not check headers'}
    
    def _test_source_comments(self) -> Dict:
        """Check for sensitive information in HTML comments"""
        try:
            r = self.session.get(self.target_url, timeout=5)
            
            comments = re.findall(r'<!--(.*?)-->', r.text, re.DOTALL)
            
            sensitive_patterns = ['password', 'secret', 'key', 'token', 'api', 'TODO', 'FIXME', 'username']
            sensitive_comments = []
            
            for comment in comments:
                if any(pattern in comment.lower() for pattern in sensitive_patterns):
                    sensitive_comments.append(comment[:100])
            
            return {
                'status': 'WARN' if sensitive_comments else 'PASS',
                'details': f"Found {len(sensitive_comments)} sensitive comments" if sensitive_comments else "No sensitive comments found",
                'recommendation': "Remove sensitive information from HTML comments" if sensitive_comments else None
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not check comments'}
    
    def _test_csp_header(self) -> Dict:
        """Check Content-Security-Policy header"""
        try:
            r = self.session.get(self.target_url, timeout=5)
            
            csp = r.headers.get('Content-Security-Policy', '')
            
            if not csp:
                return {
                    'status': 'FAIL',
                    'details': 'CSP header missing',
                    'recommendation': "Implement Content-Security-Policy header"
                }
            
            # Check for unsafe directives
            issues = []
            if "'unsafe-inline'" in csp:
                issues.append("unsafe-inline")
            if "'unsafe-eval'" in csp:
                issues.append("unsafe-eval")
            if '*' in csp:
                issues.append("wildcard source")
            
            return {
                'status': 'WARN' if issues else 'PASS',
                'details': f"CSP present. Issues: {issues}" if issues else f"CSP present: {csp[:100]}",
                'recommendation': "Remove unsafe-inline, unsafe-eval, and wildcards from CSP" if issues else None
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not check CSP'}
    
    def _test_content_type_options(self) -> Dict:
        """Check X-Content-Type-Options header"""
        try:
            r = self.session.get(self.target_url, timeout=5)
            
            xcto = r.headers.get('X-Content-Type-Options', '')
            
            return {
                'status': 'PASS' if xcto == 'nosniff' else 'FAIL',
                'details': f"X-Content-Type-Options: {xcto}" if xcto else "X-Content-Type-Options missing",
                'recommendation': "Add X-Content-Type-Options: nosniff header" if xcto != 'nosniff' else None
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not check X-Content-Type-Options'}
    
    def _test_x_frame_options(self) -> Dict:
        """Check X-Frame-Options header"""
        try:
            r = self.session.get(self.target_url, timeout=5)
            
            xfo = r.headers.get('X-Frame-Options', '')
            
            if not xfo:
                return {
                    'status': 'FAIL',
                    'details': 'X-Frame-Options missing',
                    'recommendation': "Add X-Frame-Options: DENY or SAMEORIGIN"
                }
            
            return {
                'status': 'PASS' if xfo.upper() in ['DENY', 'SAMEORIGIN'] else 'WARN',
                'details': f"X-Frame-Options: {xfo}",
                'recommendation': "Use DENY or SAMEORIGIN" if xfo.upper() not in ['DENY', 'SAMEORIGIN'] else None
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not check X-Frame-Options'}
    
    def _test_referrer_policy(self) -> Dict:
        """Check Referrer-Policy header"""
        try:
            r = self.session.get(self.target_url, timeout=5)
            
            rp = r.headers.get('Referrer-Policy', '')
            
            safe_policies = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin']
            
            return {
                'status': 'PASS' if rp in safe_policies else 'WARN',
                'details': f"Referrer-Policy: {rp}" if rp else "Referrer-Policy missing",
                'recommendation': "Set Referrer-Policy to no-referrer or strict-origin" if rp not in safe_policies else None
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not check Referrer-Policy'}
    
    def _test_feature_policy(self) -> Dict:
        """Check Feature-Policy/Permissions-Policy header"""
        try:
            r = self.session.get(self.target_url, timeout=5)
            
            fp = r.headers.get('Feature-Policy', '') or r.headers.get('Permissions-Policy', '')
            
            return {
                'status': 'WARN' if not fp else 'PASS',
                'details': f"Feature/Permissions-Policy: {fp[:100]}" if fp else "Feature-Policy/Permissions-Policy missing",
                'recommendation': "Implement Permissions-Policy header" if not fp else None
            }
        except:
            return {'status': 'ERROR', 'details': 'Could not check Feature-Policy'}
    
    def _test_host_header_injection(self) -> Dict:
        """Test for host header injection"""
        try:
            # Send request with malicious host header
            evil_host = 'evil.com'
            r = self.session.get(self.target_url, headers={'Host': evil_host}, timeout=5)
            
            # Check if evil host appears in response
            if evil_host in r.text:
                return {
                    'status': 'FAIL',
                    'details': 'Host header injection possible',
                    'recommendation': 'Validate Host header against whitelist'
                }
            
            return {'status': 'PASS', 'details': 'No host header injection detected'}
        except:
            return {'status': 'ERROR', 'details': 'Could not test host header injection'}
    
    def _test_request_smuggling(self) -> Dict:
        """Test for HTTP request smuggling"""
        return {
            'status': 'INFO',
            'details': 'Request smuggling requires specialized tools',
            'recommendation': 'Use tools like http-request-smuggler'
        }
    
    # Helper methods
    def _calculate_score(self, findings: List[Dict]) -> Dict:
        """Calculate security score for a category"""
        total = len(findings)
        if total == 0:
            return {'score': 100, 'grade': 'A'}
        
        severity_weights = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 4,
            'LOW': 2,
            'WARN': 1,
            'INFO': 0
        }
        
        deductions = 0
        for finding in findings:
            result = finding.get('result', {})
            status = result.get('status', 'PASS')
            severity = finding.get('severity', 'INFO')
            
            if status in ['FAIL', 'WARN']:
                deductions += severity_weights.get(severity, 0)
        
        max_deductions = sum(severity_weights.get(f.get('severity', 'INFO'), 0) for f in findings)
        score = max(0, 100 - int((deductions / max(max_deductions, 1)) * 100))
        
        # Assign grade
        if score >= 90:
            grade = 'A'
        elif score >= 80:
            grade = 'B'
        elif score >= 70:
            grade = 'C'
        elif score >= 60:
            grade = 'D'
        else:
            grade = 'F'
        
        return {
            'score': score,
            'grade': grade,
            'total_findings': total,
            'failed': sum(1 for f in findings if f.get('result', {}).get('status') == 'FAIL')
        }
    
    def _generate_summary(self, results: Dict) -> Dict:
        """Generate overall summary"""
        total_findings = 0
        critical = 0
        high = 0
        medium = 0
        low = 0
        info = 0
        
        for category_name, category_data in results['categories'].items():
            findings = category_data.get('findings', [])
            total_findings += len(findings)
            
            for finding in findings:
                if finding.get('result', {}).get('status') in ['FAIL', 'WARN']:
                    severity = finding.get('severity', 'INFO')
                    if severity == 'CRITICAL':
                        critical += 1
                    elif severity == 'HIGH':
                        high += 1
                    elif severity == 'MEDIUM':
                        medium += 1
                    elif severity == 'LOW':
                        low += 1
                    else:
                        info += 1
        
        # Calculate overall score
        all_scores = [cat.get('score', {}).get('score', 0) for cat in results['categories'].values()]
        overall_score = sum(all_scores) / len(all_scores) if all_scores else 0
        
        return {
            'total_checks': total_findings,
            'critical_issues': critical,
            'high_issues': high,
            'medium_issues': medium,
            'low_issues': low,
            'info_issues': info,
            'overall_score': round(overall_score, 1),
            'overall_grade': self._score_to_grade(overall_score)
        }
    
    def _score_to_grade(self, score: float) -> str:
        """Convert score to letter grade"""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
    
    def _save_results(self, results: Dict):
        """Save results to evidence directory"""
        if not self.evidence_dir:
            return

        # Save JSON
        json_path = Path(self.evidence_dir) / 'owasp_asvs_results.json'
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"\n[+] Results saved to: {json_path}")

        # Export to Enhanced CSV (NEW!)
        try:
            import sys
            sys.path.insert(0, str(Path(__file__).parent))
            from asvs_csv_exporter import get_csv_exporter

            csv_exporter = get_csv_exporter()
            csv_path = Path(self.evidence_dir) / 'owasp_asvs_detailed_results_enhanced.csv'
            csv_exporter.export_to_csv(results, str(csv_path))
        except Exception as e:
            print(f"[!] Enhanced CSV export failed: {e}")
            print(f"    Fallback: CSV can be generated manually using asvs_csv_exporter.py")

        # Print summary
        summary = results.get('summary', {})
        print("\n" + "="*70)
        print("OWASP ASVS ASSESSMENT SUMMARY")
        print("="*70)
        print(f"Overall Score: {summary.get('overall_score')}/100 (Grade: {summary.get('overall_grade')})")
        print(f"Total Checks: {summary.get('total_checks')}")
        print(f"\nIssues Found:")
        print(f"  CRITICAL: {summary.get('critical_issues')}")
        print(f"  HIGH:     {summary.get('high_issues')}")
        print(f"  MEDIUM:   {summary.get('medium_issues')}")
        print(f"  LOW:      {summary.get('low_issues')}")
        print(f"  INFO:     {summary.get('info_issues')}")
        print("="*70)


# CLI interface
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 owasp_asvs_scanner.py <target_url> [evidence_dir]")
        print("Example: python3 owasp_asvs_scanner.py http://example.com ./evidence")
        sys.exit(1)
    
    target = sys.argv[1]
    evidence_dir = sys.argv[2] if len(sys.argv) > 2 else None
    
    scanner = OWASPASVSScanner(target, evidence_dir)
    results = scanner.scan()
    
    print("\n[+] Assessment complete!")


# ============================================================================
# LAZY INITIALIZATION PATTERN FOR AUTO-INIT (MCP Server)
# ============================================================================

_asvs_scanner_instance = None

def get_asvs_scanner(target_url: str = None, evidence_dir: str = None):
    """
    Factory function for lazy initialization of OWASP ASVS Scanner.
    
    This allows the MCP server to import this module without requiring
    a target_url parameter, deferring initialization until first use.
    
    Args:
        target_url: Target URL to scan (required on first call)
        evidence_dir: Directory for evidence collection (optional)
        
    Returns:
        OWASPASVSScanner: Singleton scanner instance
        
    Raises:
        ValueError: If scanner not initialized with target_url
        
    Usage:
        # In MCP server auto-init:
        from owasp_asvs_scanner import get_asvs_scanner
        # No error - just imports the factory function
        
        # When ready to scan:
        scanner = get_asvs_scanner("http://example.com", "evidence/scan1")
        results = scanner.scan()
        
        # Subsequent calls reuse the same instance:
        scanner2 = get_asvs_scanner()  # Returns same scanner
    """
    global _asvs_scanner_instance
    
    # If target_url provided, create/update instance
    if target_url:
        _asvs_scanner_instance = OWASPASVSScanner(target_url, evidence_dir)
        return _asvs_scanner_instance
    
    # If no target_url and no instance, raise error
    if _asvs_scanner_instance is None:
        raise ValueError(
            "ASVS Scanner not initialized. "
            "Call get_asvs_scanner(target_url) first."
        )
    
    # Return existing instance
    return _asvs_scanner_instance
