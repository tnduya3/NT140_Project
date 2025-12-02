// Feature Extractor - Static analysis of JS code
const FeatureExtractor = {
  
  // Extract all features from JS code
  async extractFeatures(code, url) {
    const startTime = Date.now();
    
    // Try multiple parse strategies
    let ast = null;
    let parseError = null;
    
    // Strategy 1: Try as script with ES2022
    try {
      ast = acorn.parse(code, {
        ecmaVersion: 2022,
        sourceType: 'script',
        locations: false
      });
    } catch (e1) {
      parseError = e1;
      
      // Strategy 2: Try as module (for import/export)
      try {
        ast = acorn.parse(code, {
          ecmaVersion: 2022,
          sourceType: 'module',
          locations: false
        });
        parseError = null;
      } catch (e2) {
        // Strategy 3: Try with older ES version
        try {
          ast = acorn.parse(code, {
            ecmaVersion: 2020,
            sourceType: 'script',
            locations: false,
            allowReturnOutsideFunction: true
          });
          parseError = null;
        } catch (e3) {
          parseError = e3;
        }
      }
    }
    
    // If all parse strategies failed, use fallback
    if (!ast) {
      console.warn('[Feature Extractor] Parse failed, using fallback analysis:', parseError.message);
      return {
        success: true, // Still return success but with limited features
        features: this.getFallbackFeatures(code, url),
        parseError: parseError.message
      };
    }
    
    try {
      const features = {
        url: url,
        codeSize: code.length,
        timestamp: Date.now(),
        
        // Dangerous function calls
        dangerousFunctions: this.countDangerousFunctions(ast, code),
        
        // URL analysis
        urlAnalysis: this.analyzeURLs(code, url),
        
        // Obfuscation detection
        obfuscation: this.detectObfuscation(code, ast),
        
        // Code complexity
        complexity: this.calculateComplexity(ast),
        
        // String analysis
        stringAnalysis: this.analyzeStrings(code, ast),
        
        // Suspicious patterns
        suspiciousPatterns: this.detectSuspiciousPatterns(ast, code),

        // Network matches (IPs/domains)
        networkMatches: {
          ips: [], // literal IPs found in code
          blacklistedIps: [] // matches from local IP DB (if available)
        },
        
        // Extraction time
        extractionTime: Date.now() - startTime
      };
      // Detect IP literals in code (IPv4 basic pattern) and check against IpDB if present
      try {
        const ipRegex = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
        const ips = Array.from(new Set((code.match(ipRegex) || []).map(s => s.trim())));
        features.networkMatches.ips = ips;

        if (typeof IpDB !== 'undefined' && IpDB && IpDB.isIpBlacklisted) {
          for (const ip of ips) {
            try {
              const res = await IpDB.isIpBlacklisted(ip);
              if (res && res.found) {
                features.networkMatches.blacklistedIps.push(res);
              }
            } catch (e) {
              // ignore per-IP errors
            }
          }
        } else {
          // Also check URL domains that are numeric IPs
          for (const d of features.urlAnalysis.domains || []) {
            if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(d)) {
              features.networkMatches.ips.push(d);
              if (typeof IpDB !== 'undefined' && IpDB && IpDB.isIpBlacklisted) {
                try {
                  const res = await IpDB.isIpBlacklisted(d);
                  if (res && res.found) features.networkMatches.blacklistedIps.push(res);
                } catch (e) {}
              }
            }
          }
        }
      } catch (e) {
        // non-fatal
      }

      return { success: true, features };
      
    } catch (error) {
      console.error('[Feature Extractor] Feature extraction error:', error);
      return {
        success: true,
        features: this.getFallbackFeatures(code, url),
        extractionError: error.message
      };
    }
  },
  
  // Count dangerous function calls
  countDangerousFunctions(ast, code) {
    const counts = {
      eval: 0,
      Function: 0,
      setTimeout_string: 0,
      setInterval_string: 0,
      document_write: 0,
      atob: 0,
      btoa: 0,
      unescape: 0,
      decodeURIComponent: 0,
      innerHTML: 0,
      outerHTML: 0
    };
    
    // Walk AST
    this.walkAST(ast, (node) => {
      // eval()
      if (node.type === 'CallExpression' && node.callee.name === 'eval') {
        counts.eval++;
      }
      
      // Function constructor
      if (node.type === 'NewExpression' && node.callee.name === 'Function') {
        counts.Function++;
      }
      
      // setTimeout/setInterval with string
      if (node.type === 'CallExpression') {
        if (node.callee.name === 'setTimeout' || node.callee.name === 'setInterval') {
          if (node.arguments[0] && node.arguments[0].type === 'Literal') {
            if (node.callee.name === 'setTimeout') counts.setTimeout_string++;
            else counts.setInterval_string++;
          }
        }
        
        // document.write
        if (node.callee.type === 'MemberExpression' &&
            node.callee.object.name === 'document' &&
            node.callee.property.name === 'write') {
          counts.document_write++;
        }
        
        // atob, btoa, unescape, decodeURIComponent
        if (node.callee.name === 'atob') counts.atob++;
        if (node.callee.name === 'btoa') counts.btoa++;
        if (node.callee.name === 'unescape') counts.unescape++;
        if (node.callee.name === 'decodeURIComponent') counts.decodeURIComponent++;
      }
      
      // innerHTML, outerHTML assignments
      if (node.type === 'AssignmentExpression' &&
          node.left.type === 'MemberExpression') {
        if (node.left.property.name === 'innerHTML') counts.innerHTML++;
        if (node.left.property.name === 'outerHTML') counts.outerHTML++;
      }
    });
    
    counts.total = Object.values(counts).reduce((a, b) => a + b, 0);
    return counts;
  },
  
  // Analyze URLs in code
  analyzeURLs(code, scriptUrl) {
    const urlRegex = /https?:\/\/[^\s"'`<>)]+/gi;
    const urls = code.match(urlRegex) || [];
    
    // Get script domain
    let scriptDomain = '';
    try {
      scriptDomain = new URL(scriptUrl).hostname;
    } catch (e) {}
    
    // Count external URLs
    let externalCount = 0;
    const domains = new Set();
    
    urls.forEach(url => {
      try {
        const urlObj = new URL(url);
        domains.add(urlObj.hostname);
        if (urlObj.hostname !== scriptDomain) {
          externalCount++;
        }
      } catch (e) {}
    });
    
    return {
      totalUrls: urls.length,
      uniqueDomains: domains.size,
      externalUrls: externalCount,
      externalPercentage: urls.length > 0 ? (externalCount / urls.length * 100).toFixed(2) : 0,
      domains: Array.from(domains)
    };
  },
  
  // Detect obfuscation
  detectObfuscation(code, ast) {
    const indicators = {
      hexStrings: (code.match(/\\x[0-9a-f]{2}/gi) || []).length,
      unicodeEscapes: (code.match(/\\u[0-9a-f]{4}/gi) || []).length,
      base64Strings: this.countBase64Strings(code),
      longIdentifiers: this.countLongIdentifiers(ast),
      stringConcatenation: this.countStringConcatenation(ast),
      charCodeUsage: (code.match(/String\.fromCharCode|charCodeAt/g) || []).length
    };
    
    // Calculate obfuscation score
    let score = 0;
    if (indicators.hexStrings > 10) score += 20;
    if (indicators.unicodeEscapes > 10) score += 20;
    if (indicators.base64Strings > 5) score += 15;
    if (indicators.longIdentifiers > 5) score += 10;
    if (indicators.stringConcatenation > 20) score += 15;
    if (indicators.charCodeUsage > 5) score += 20;
    
    return {
      ...indicators,
      score: Math.min(score, 100),
      isObfuscated: score > 40
    };
  },
  
  // Calculate code complexity
  calculateComplexity(ast) {
    let loops = 0;
    let conditionals = 0;
    let functions = 0;
    let maxNestingDepth = 0;
    let currentDepth = 0;
    
    this.walkAST(ast, (node, depth) => {
      currentDepth = depth || 0;
      if (currentDepth > maxNestingDepth) maxNestingDepth = currentDepth;
      
      if (node.type === 'ForStatement' || 
          node.type === 'WhileStatement' || 
          node.type === 'DoWhileStatement' ||
          node.type === 'ForInStatement' ||
          node.type === 'ForOfStatement') {
        loops++;
      }
      
      if (node.type === 'IfStatement' || 
          node.type === 'SwitchStatement' ||
          node.type === 'ConditionalExpression') {
        conditionals++;
      }
      
      if (node.type === 'FunctionDeclaration' || 
          node.type === 'FunctionExpression' ||
          node.type === 'ArrowFunctionExpression') {
        functions++;
      }
    });
    
    // Cyclomatic complexity approximation
    const cyclomaticComplexity = 1 + conditionals + loops;
    
    return {
      loops,
      conditionals,
      functions,
      maxNestingDepth,
      cyclomaticComplexity
    };
  },
  
  // Analyze strings
  analyzeStrings(code, ast) {
    const strings = [];
    
    this.walkAST(ast, (node) => {
      if (node.type === 'Literal' && typeof node.value === 'string') {
        strings.push(node.value);
      }
    });
    
    // Calculate entropy
    const entropies = strings.map(s => this.calculateEntropy(s));
    const avgEntropy = entropies.length > 0 
      ? entropies.reduce((a, b) => a + b, 0) / entropies.length 
      : 0;
    const maxEntropy = entropies.length > 0 ? Math.max(...entropies) : 0;
    
    // High entropy strings (likely obfuscated)
    const highEntropyStrings = strings.filter((s, i) => entropies[i] > 4.5).length;
    
    return {
      totalStrings: strings.length,
      avgEntropy: avgEntropy.toFixed(3),
      maxEntropy: maxEntropy.toFixed(3),
      highEntropyStrings,
      avgStringLength: strings.length > 0 
        ? (strings.reduce((a, s) => a + s.length, 0) / strings.length).toFixed(1)
        : 0
    };
  },
  
  // Detect suspicious patterns
  detectSuspiciousPatterns(ast, code) {
    const patterns = {
      dynamicPropertyAccess: 0,
      importScripts: 0,
      webSocket: 0,
      xhr: 0,
      fetch: 0,
      postMessage: 0,
      localStorage: 0,
      cookie: 0
    };
    
    this.walkAST(ast, (node) => {
      // Dynamic property access: window["eval"], this["Function"]
      if (node.type === 'MemberExpression' && node.computed) {
        patterns.dynamicPropertyAccess++;
      }
      
      // importScripts
      if (node.type === 'CallExpression' && node.callee.name === 'importScripts') {
        patterns.importScripts++;
      }
      
      // WebSocket
      if (node.type === 'NewExpression' && node.callee.name === 'WebSocket') {
        patterns.webSocket++;
      }
      
      // XMLHttpRequest
      if (node.type === 'NewExpression' && node.callee.name === 'XMLHttpRequest') {
        patterns.xhr++;
      }
      
      // fetch
      if (node.type === 'CallExpression' && node.callee.name === 'fetch') {
        patterns.fetch++;
      }
      
      // postMessage
      if (node.type === 'CallExpression' && 
          node.callee.type === 'MemberExpression' &&
          node.callee.property.name === 'postMessage') {
        patterns.postMessage++;
      }
      
      // localStorage
      if (node.type === 'MemberExpression' && 
          node.object.name === 'localStorage') {
        patterns.localStorage++;
      }
      
      // document.cookie
      if (node.type === 'MemberExpression' &&
          node.object.name === 'document' &&
          node.property.name === 'cookie') {
        patterns.cookie++;
      }
    });
    
    return patterns;
  },
  
  // Helper: Walk AST recursively
  walkAST(node, callback, depth = 0) {
    if (!node || typeof node !== 'object') return;
    
    callback(node, depth);
    
    for (const key in node) {
      if (key === 'loc' || key === 'range') continue;
      const child = node[key];
      
      if (Array.isArray(child)) {
        child.forEach(c => this.walkAST(c, callback, depth + 1));
      } else if (child && typeof child === 'object') {
        this.walkAST(child, callback, depth + 1);
      }
    }
  },
  
  // Helper: Calculate Shannon entropy
  calculateEntropy(str) {
    if (!str || str.length === 0) return 0;
    
    const freq = {};
    for (let i = 0; i < str.length; i++) {
      freq[str[i]] = (freq[str[i]] || 0) + 1;
    }
    
    let entropy = 0;
    const len = str.length;
    for (const char in freq) {
      const p = freq[char] / len;
      entropy -= p * Math.log2(p);
    }
    
    return entropy;
  },
  
  // Helper: Count base64 strings
  countBase64Strings(code) {
    // Base64 pattern: at least 20 chars, ends with = or ==
    const base64Regex = /[A-Za-z0-9+/]{20,}={0,2}/g;
    const matches = code.match(base64Regex) || [];
    
    // Filter out false positives
    return matches.filter(m => {
      // Check if it's likely base64
      const validChars = m.match(/[A-Za-z0-9+/]/g).length;
      return validChars / m.length > 0.9;
    }).length;
  },
  
  // Helper: Count long identifiers (obfuscation indicator)
  countLongIdentifiers(ast) {
    let count = 0;
    
    this.walkAST(ast, (node) => {
      if (node.type === 'Identifier' && node.name.length > 30) {
        count++;
      }
    });
    
    return count;
  },
  
  // Helper: Count string concatenation
  countStringConcatenation(ast) {
    let count = 0;
    
    this.walkAST(ast, (node) => {
      if (node.type === 'BinaryExpression' && node.operator === '+') {
        // Check if either side is a string
        if ((node.left.type === 'Literal' && typeof node.left.value === 'string') ||
            (node.right.type === 'Literal' && typeof node.right.value === 'string')) {
          count++;
        }
      }
    });
    
    return count;
  },
  
  // Fallback features when parsing fails
  getFallbackFeatures(code, url) {
    return {
      url: url,
      codeSize: code.length,
      timestamp: Date.now(),
      parseError: true,
      
      // Basic regex-based analysis
      dangerousFunctions: {
        eval: (code.match(/\beval\s*\(/g) || []).length,
        Function: (code.match(/new\s+Function\s*\(/g) || []).length,
        setTimeout_string: 0,
        setInterval_string: 0,
        document_write: (code.match(/document\.write/g) || []).length,
        atob: (code.match(/\batob\s*\(/g) || []).length,
        btoa: (code.match(/\bbtoa\s*\(/g) || []).length,
        unescape: (code.match(/\bunescape\s*\(/g) || []).length,
        decodeURIComponent: (code.match(/\bdecodeURIComponent\s*\(/g) || []).length,
        innerHTML: (code.match(/\.innerHTML/g) || []).length,
        outerHTML: (code.match(/\.outerHTML/g) || []).length
      },
      
      urlAnalysis: {
        totalUrls: (code.match(/https?:\/\//g) || []).length,
        externalUrls: (code.match(/https?:\/\//g) || []).length,
        externalPercentage: '100',
        uniqueDomains: 0,
        domains: []
      },
      
      obfuscation: {
        hexStrings: (code.match(/\\x[0-9a-f]{2}/gi) || []).length,
        unicodeEscapes: (code.match(/\\u[0-9a-f]{4}/gi) || []).length,
        base64Strings: (code.match(/[A-Za-z0-9+/]{20,}={0,2}/g) || []).length,
        charCodeUsage: (code.match(/charCodeAt|fromCharCode/g) || []).length,
        isObfuscated: false,
        score: 0
      },
      
      complexity: {
        loops: (code.match(/\b(for|while|do)\b/g) || []).length,
        conditionals: (code.match(/\b(if|else|switch|case)\b/g) || []).length,
        functions: (code.match(/\bfunction\b/g) || []).length,
        maxNestingDepth: 0,
        cyclomaticComplexity: 0
      },
      
      stringAnalysis: {
        totalStrings: (code.match(/(["'`])[^\1]*?\1/g) || []).length,
        avgEntropy: '0',
        maxEntropy: '0',
        highEntropyStrings: 0
      },
      
      suspiciousPatterns: {
        dynamicPropertyAccess: (code.match(/\[["'`][^\]]+["'`]\]/g) || []).length,
        importScripts: (code.match(/importScripts/g) || []).length,
        webSocket: (code.match(/WebSocket/g) || []).length,
        xhr: (code.match(/XMLHttpRequest/g) || []).length,
        fetch: (code.match(/\bfetch\s*\(/g) || []).length,
        cookie: (code.match(/document\.cookie/g) || []).length
      }
    };
  }
};
