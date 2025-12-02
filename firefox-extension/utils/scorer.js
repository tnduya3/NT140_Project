// Rule-based Scorer - Calculate risk score from features
const Scorer = {
  
  // Trusted CDN and library domains (auto-whitelist)
  trustedDomains: [
    'cdnjs.cloudflare.com', 'unpkg.com', 'jsdelivr.net', 'cdn.jsdelivr.net',
    'ajax.googleapis.com', 'code.jquery.com', 'stackpath.bootstrapcdn.com',
    'maxcdn.bootstrapcdn.com', 'use.fontawesome.com', 'fonts.googleapis.com',
    'cdn.bootcss.com', 'cdn.staticfile.org', 'lib.baomitu.com',
    'polyfill.io', 'cdnjs.com', 'unpkg.org'
  ],
  
  // Suspicious domains (common malware/phishing patterns)
  suspiciousDomains: [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', // URL shorteners
    '.tk', '.ml', '.ga', '.cf', '.gq', // Free TLDs
    'pastebin.com', 'hastebin.com' // Code sharing
  ],

  // Weight to give when an IP is found in blacklist
  ipWeight: 40,
  
  // Check if URL is from trusted source
  isTrustedSource(url) {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();
      
      // Check trusted domains
      for (const trusted of this.trustedDomains) {
        if (hostname === trusted || hostname.endsWith('.' + trusted)) {
          return true;
        }
      }
      
      // Check for common library paths
      const path = urlObj.pathname.toLowerCase();
      if (path.includes('/lib/') || path.includes('/vendor/') || 
          path.includes('/node_modules/') || path.includes('/dist/')) {
        return true;
      }
      
      return false;
    } catch (e) {
      return false;
    }
  },
  
  // Calculate overall risk score (0-100) with multi-factor assessment
  calculateScore(features, hashMatch = null) {
    let score = 0;
    const breakdown = {};
    
    // Check if from trusted source first
    const isTrusted = this.isTrustedSource(features.url);
    breakdown.trustedSource = isTrusted;
    
    // If trusted source, reduce all scores
    const trustMultiplier = isTrusted ? 0.3 : 1.0;
    
    // 1. Hash match from Tempico (max 40 points, not auto-block)
    let hashScore = 0;
    if (hashMatch && hashMatch.found) {
      hashScore = 40;
      breakdown.hashMatch = hashScore;
    }
    score += hashScore;
    
    // 2. Dangerous functions (max 30 points)
    const dangerScore = this.scoreDangerousFunctions(features.dangerousFunctions) * trustMultiplier;
    score += dangerScore;
    breakdown.dangerousFunctions = Math.round(dangerScore);
    
    // 3. Obfuscation (max 20 points)
    const obfuscationScore = this.scoreObfuscation(features.obfuscation) * trustMultiplier;
    score += obfuscationScore;
    breakdown.obfuscation = Math.round(obfuscationScore);
    
    // 4. External URLs (max 10 points)
    const urlScore = this.scoreURLs(features.urlAnalysis) * trustMultiplier;
    score += urlScore;
    breakdown.urls = Math.round(urlScore);
    
    // 5. String entropy (max 15 points)
    const entropyScore = this.scoreEntropy(features.stringAnalysis) * trustMultiplier;
    score += entropyScore;
    breakdown.entropy = Math.round(entropyScore);
    
    // 6. Suspicious patterns (max 20 points)
    const patternScore = this.scoreSuspiciousPatterns(features.suspiciousPatterns) * trustMultiplier;
    score += patternScore;
    breakdown.patterns = Math.round(patternScore);
    
    // 7. Code complexity (max 10 points)
    const complexityScore = this.scoreComplexity(features.complexity) * trustMultiplier;
    score += complexityScore;
    breakdown.complexity = Math.round(complexityScore);
    
    // 8. Suspicious domains (max 20 points)
    const domainScore = this.scoreDomains(features.urlAnalysis) * trustMultiplier;
    score += domainScore;
    breakdown.domains = Math.round(domainScore);
    
    // 9. Unknown domain penalty (max 10 points)
    let unknownDomainScore = 0;
    if (!isTrusted && !this.isKnownDomain(features.url)) {
      unknownDomainScore = 10;
    }
    score += unknownDomainScore;
    breakdown.unknownDomain = unknownDomainScore;

    // 10. IP blacklist (configurable weight)
    const ipWeight = this.ipWeight || 40;
    let ipScore = 0;
    if (features.networkMatches && features.networkMatches.blacklistedIps && features.networkMatches.blacklistedIps.length > 0) {
      ipScore = ipWeight;
    }
    score += ipScore;
    breakdown.ipMatches = ipScore;
    
    // Cap at 100
    score = Math.min(score, 100);
    
    // Determine risk level - ONLY block if >= 70
    let riskLevel = 'low';
    let action = 'allow';
    
    if (score >= 70) {
      riskLevel = 'high';
      action = 'block';
    } else if (score >= 40) {
      riskLevel = 'medium';
      action = 'suspect';
    }
    
    return {
      score: Math.round(score),
      riskLevel,
      action,
      breakdown,
      isTrusted,
      reasons: this.generateReasons(features, breakdown, hashMatch)
    };
  },
  
  // Check if domain is known (not necessarily trusted, but recognized)
  isKnownDomain(url) {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();
      
      // Check if it's a well-known TLD
      const knownTLDs = ['.com', '.org', '.net', '.edu', '.gov', '.io', '.co'];
      const hasKnownTLD = knownTLDs.some(tld => hostname.endsWith(tld));
      
      // Check if domain has reasonable length (not DGA)
      const domainParts = hostname.split('.');
      const mainDomain = domainParts[domainParts.length - 2] || '';
      const isReasonableLength = mainDomain.length <= 20;
      
      return hasKnownTLD && isReasonableLength;
    } catch (e) {
      return false;
    }
  },
  
  // Score dangerous functions (reduced max to 30)
  scoreDangerousFunctions(dangerous) {
    let score = 0;
    
    // eval() - very dangerous
    score += Math.min(dangerous.eval * 10, 30);
    
    // Function constructor - very dangerous
    score += Math.min(dangerous.Function * 10, 30);
    
    // setTimeout/setInterval with string - dangerous
    score += Math.min((dangerous.setTimeout_string + dangerous.setInterval_string) * 8, 20);
    
    // document.write - moderate
    score += Math.min(dangerous.document_write * 3, 10);
    
    // Encoding/decoding functions - suspicious
    score += Math.min((dangerous.atob + dangerous.btoa) * 3, 15);
    score += Math.min((dangerous.unescape + dangerous.decodeURIComponent) * 2, 10);
    
    // innerHTML/outerHTML - moderate
    score += Math.min((dangerous.innerHTML + dangerous.outerHTML) * 2, 10);
    
    return Math.min(score, 30);
  },
  
  // Score obfuscation (reduced max to 20)
  scoreObfuscation(obfuscation) {
    let score = 0;
    
    // Use pre-calculated obfuscation score
    score += obfuscation.score * 0.20; // Scale to max 20
    
    // Additional penalties
    if (obfuscation.hexStrings > 50) score += 8;
    if (obfuscation.unicodeEscapes > 50) score += 8;
    if (obfuscation.charCodeUsage > 10) score += 8;
    
    return Math.min(score, 20);
  },
  
  // Score URL analysis (reduced max to 10)
  scoreURLs(urlAnalysis) {
    let score = 0;
    
    // High percentage of external URLs
    const extPercent = parseFloat(urlAnalysis.externalPercentage);
    if (extPercent > 80) score += 10;
    else if (extPercent > 50) score += 6;
    else if (extPercent > 30) score += 3;
    
    // Too many URLs
    if (urlAnalysis.totalUrls > 20) score += 3;
    if (urlAnalysis.totalUrls > 50) score += 6;
    
    return Math.min(score, 10);
  },
  
  // Score string entropy (reduced max to 15)
  scoreEntropy(stringAnalysis) {
    let score = 0;
    
    const avgEntropy = parseFloat(stringAnalysis.avgEntropy);
    const maxEntropy = parseFloat(stringAnalysis.maxEntropy);
    
    // High average entropy
    if (avgEntropy > 4.5) score += 10;
    else if (avgEntropy > 4.0) score += 6;
    else if (avgEntropy > 3.5) score += 3;
    
    // High max entropy
    if (maxEntropy > 5.0) score += 6;
    
    // Many high entropy strings
    if (stringAnalysis.highEntropyStrings > 10) score += 6;
    else if (stringAnalysis.highEntropyStrings > 5) score += 3;
    
    return Math.min(score, 15);
  },
  
  // Score suspicious patterns (reduced max to 20)
  scoreSuspiciousPatterns(patterns) {
    let score = 0;
    
    // Dynamic property access (evasion technique)
    if (patterns.dynamicPropertyAccess > 10) score += 12;
    else if (patterns.dynamicPropertyAccess > 5) score += 8;
    else if (patterns.dynamicPropertyAccess > 0) score += 4;
    
    // importScripts (can load malicious code)
    score += Math.min(patterns.importScripts * 8, 16);
    
    // WebSocket (data exfiltration)
    if (patterns.webSocket > 0) score += 8;
    
    // Network requests
    const networkCalls = patterns.xhr + patterns.fetch;
    if (networkCalls > 10) score += 8;
    else if (networkCalls > 5) score += 4;
    
    // Cookie access (data theft)
    if (patterns.cookie > 3) score += 8;
    else if (patterns.cookie > 0) score += 4;
    
    return Math.min(score, 20);
  },
  
  // Score code complexity
  scoreComplexity(complexity) {
    let score = 0;
    
    // Very high complexity can indicate obfuscation
    if (complexity.cyclomaticComplexity > 100) score += 10;
    else if (complexity.cyclomaticComplexity > 50) score += 5;
    
    // Deep nesting
    if (complexity.maxNestingDepth > 10) score += 5;
    
    return Math.min(score, 10);
  },
  
  // Score suspicious domains (reduced max to 20)
  scoreDomains(urlAnalysis) {
    let score = 0;
    
    if (!urlAnalysis.domains) return 0;
    
    for (const domain of urlAnalysis.domains) {
      // Check against suspicious domain list
      for (const suspicious of this.suspiciousDomains) {
        if (domain.includes(suspicious)) {
          score += 12;
          break;
        }
      }
      
      // Check for IP addresses
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
        score += 8;
      }
      
      // Very long domain (possible DGA)
      if (domain.length > 40) {
        score += 4;
      }
    }
    
    return Math.min(score, 20);
  },
  
  // Generate human-readable reasons
  generateReasons(features, breakdown, hashMatch = null) {
    const reasons = [];
    
    // Hash match
    if (breakdown.hashMatch) {
      reasons.push(`⚠️ Hash trùng với database mã độc (${hashMatch.source || 'Tempico'})`);
    }

    // IP matches
    if (features.networkMatches && features.networkMatches.blacklistedIps && features.networkMatches.blacklistedIps.length > 0) {
      for (const ip of features.networkMatches.blacklistedIps) {
        const ipText = ip && ip.ip ? ip.ip : (ip && ip.meta && ip.meta.IP) || JSON.stringify(ip);
        reasons.push(`⚠️ Kết nối đến IP danh sách đen: ${ipText}`);
      }
    }
    
    // Trusted source
    if (breakdown.trustedSource) {
      reasons.push('✓ Nguồn tin cậy (CDN/thư viện phổ biến)');
    }
    
    // Unknown domain
    if (breakdown.unknownDomain > 0) {
      reasons.push('Domain không rõ nguồn gốc');
    }
    
    // Dangerous functions
    if (breakdown.dangerousFunctions > 15) {
      const d = features.dangerousFunctions;
      if (d.eval > 0) reasons.push(`Sử dụng eval() ${d.eval} lần`);
      if (d.Function > 0) reasons.push(`Sử dụng Function constructor ${d.Function} lần`);
      if (d.setTimeout_string > 0) reasons.push(`setTimeout/setInterval với string`);
    }
    
    // Obfuscation
    if (breakdown.obfuscation > 10) {
      const o = features.obfuscation;
      if (o.isObfuscated) reasons.push('Code bị obfuscate');
      if (o.hexStrings > 20) reasons.push(`Nhiều hex strings (${o.hexStrings})`);
      if (o.base64Strings > 5) reasons.push(`Nhiều base64 strings (${o.base64Strings})`);
    }
    
    // URLs
    if (breakdown.urls > 6) {
      const u = features.urlAnalysis;
      if (u.externalPercentage > 50) {
        reasons.push(`${u.externalPercentage}% URLs external`);
      }
    }
    
    // Entropy
    if (breakdown.entropy > 8) {
      const s = features.stringAnalysis;
      if (s.highEntropyStrings > 5) {
        reasons.push(`${s.highEntropyStrings} strings có entropy cao`);
      }
    }
    
    // Patterns
    if (breakdown.patterns > 8) {
      const p = features.suspiciousPatterns;
      if (p.dynamicPropertyAccess > 5) {
        reasons.push('Dynamic property access (evasion)');
      }
      if (p.webSocket > 0) reasons.push('Sử dụng WebSocket');
      if (p.cookie > 0) reasons.push('Truy cập cookies');
    }
    
    // Domains
    if (breakdown.domains > 8) {
      reasons.push('Kết nối đến domains đáng ngờ');
    }
    
    return reasons;
  },
  
  // Export features to JSON for ML training
  exportForML(features, score, label = null) {
    return {
      // Metadata
      url: features.url,
      timestamp: features.timestamp,
      label: label, // 'malware', 'benign', or null
      
      // Features for ML
      features: {
        // Dangerous functions
        eval_count: features.dangerousFunctions.eval,
        function_constructor_count: features.dangerousFunctions.Function,
        settimeout_string_count: features.dangerousFunctions.setTimeout_string,
        setinterval_string_count: features.dangerousFunctions.setInterval_string,
        document_write_count: features.dangerousFunctions.document_write,
        atob_count: features.dangerousFunctions.atob,
        btoa_count: features.dangerousFunctions.btoa,
        
        // URLs
        total_urls: features.urlAnalysis.totalUrls,
        external_url_percentage: parseFloat(features.urlAnalysis.externalPercentage),
        unique_domains: features.urlAnalysis.uniqueDomains,
        
        // Obfuscation
        hex_strings: features.obfuscation.hexStrings,
        unicode_escapes: features.obfuscation.unicodeEscapes,
        base64_strings: features.obfuscation.base64Strings,
        obfuscation_score: features.obfuscation.score,
        
        // Strings
        avg_entropy: parseFloat(features.stringAnalysis.avgEntropy),
        max_entropy: parseFloat(features.stringAnalysis.maxEntropy),
        high_entropy_strings: features.stringAnalysis.highEntropyStrings,
        
        // Complexity
        loops: features.complexity.loops,
        conditionals: features.complexity.conditionals,
        functions: features.complexity.functions,
        max_nesting_depth: features.complexity.maxNestingDepth,
        cyclomatic_complexity: features.complexity.cyclomaticComplexity,
        
        // Patterns
        dynamic_property_access: features.suspiciousPatterns.dynamicPropertyAccess,
        websocket_usage: features.suspiciousPatterns.webSocket,
        xhr_count: features.suspiciousPatterns.xhr,
        fetch_count: features.suspiciousPatterns.fetch,
        cookie_access: features.suspiciousPatterns.cookie,
        
        // Code size
        code_size: features.codeSize
      },
      
      // Score
      risk_score: score.score,
      risk_level: score.riskLevel
    };
  }
};
