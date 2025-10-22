class StringAnalyzer {
    constructor() {
		this.initializeEventListeners();
		this.setupRealtimeAnalysis();
    }

	initializeEventListeners() {
		const deepScanBtn = document.getElementById('deepScanBtn');
		if (deepScanBtn) deepScanBtn.addEventListener('click', () => this.deepScan());

		const compareBtn = document.getElementById('compareBtn');
		if (compareBtn) compareBtn.addEventListener('click', () => this.openCompare());

		document.querySelectorAll('.example-btn').forEach(btn => {
			btn.addEventListener('click', (e) => {
				const example = e.target.getAttribute('data-example');
				document.getElementById('inputString').value = example;
				this.analyzeString();
			});
		});
	}

	setupRealtimeAnalysis() {
		const input = document.getElementById('inputString');
		if (!input) return;
		input.addEventListener('input', () => {
			const value = input.value.trim();
			this.updateRealtimePanels(value);
			this.updateConfidenceMeter(0);
		});
	}

    analyzeString() {
        const input = document.getElementById('inputString').value.trim();
        if (!input) {
            alert('Please enter a string to analyze.');
            return;
        }

        const results = this.performAnalysis(input);
        this.displayResults(results);
    }

	performAnalysis(input) {
        const detections = [];
        
        // Hash detection
        detections.push(...this.detectHashes(input));
        
        // Encryption detection
		detections.push(...this.detectEncryption(input));

		// Blockchain / crypto ecosystem detection
		detections.push(...this.detectBlockchain(input));
        
        // General patterns
        detections.push(...this.detectGeneralPatterns(input));

		const overallResult = this.determineOverallResult(detections);
		const confidence = this.computeConfidenceScore(detections, input);
		const narrative = this.buildNarrative({ input, detections, overall: overallResult, confidence });

		return {
            input: input,
            detections: detections,
			overallResult: overallResult,
			confidence,
			narrative
        };
    }

    detectHashes(input) {
        const hashDetections = [];

        // MD5 (32 hex characters)
        if (/^[a-f0-9]{32}$/i.test(input)) {
            hashDetections.push({
                type: 'MD5 Hash',
                confidence: 'high',
                details: '32-character hexadecimal string matching MD5 format'
            });
        }

        // SHA1 (40 hex characters)
        if (/^[a-f0-9]{40}$/i.test(input)) {
            hashDetections.push({
                type: 'SHA1 Hash',
                confidence: 'high',
                details: '40-character hexadecimal string matching SHA1 format'
            });
        }

        // SHA256 (64 hex characters)
        if (/^[a-f0-9]{64}$/i.test(input)) {
            hashDetections.push({
                type: 'SHA256 Hash',
                confidence: 'high',
                details: '64-character hexadecimal string matching SHA256 format'
            });
        }

        // SHA512 (128 hex characters)
        if (/^[a-f0-9]{128}$/i.test(input)) {
            hashDetections.push({
                type: 'SHA512 Hash',
                confidence: 'high',
                details: '128-character hexadecimal string matching SHA512 format'
            });
        }

        // bcrypt (starts with $2a$, $2b$, $2x$, or $2y$)
        if (/^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(input)) {
            hashDetections.push({
                type: 'bcrypt Hash',
                confidence: 'high',
                details: 'bcrypt format with salt and cost factor'
            });
        }

        // Argon2 (starts with $argon2)
        if (/^\$argon2[di]\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]+={0,2}$/.test(input)) {
            hashDetections.push({
                type: 'Argon2 Hash',
                confidence: 'high',
                details: 'Argon2 password hashing function'
            });
        }

        // PBKDF2 (starts with $pbkdf2)
        if (/^\$pbkdf2-\w+\$\d+\$[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]+={0,2}$/.test(input)) {
            hashDetections.push({
                type: 'PBKDF2 Hash',
                confidence: 'high',
                details: 'PBKDF2 key derivation function'
            });
        }

        // scrypt (starts with $scrypt$)
        if (/^\$scrypt\$[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]+={0,2}$/.test(input)) {
            hashDetections.push({
                type: 'scrypt Hash',
                confidence: 'high',
                details: 'scrypt password hashing function'
            });
        }

        // NTLM (32 hex characters, often uppercase)
        if (/^[A-F0-9]{32}$/.test(input)) {
            hashDetections.push({
                type: 'NTLM Hash',
                confidence: 'medium',
                details: '32-character uppercase hexadecimal, likely NTLM hash'
            });
        }

        // LM Hash (16 hex characters)
        if (/^[A-F0-9]{16}$/.test(input)) {
            hashDetections.push({
                type: 'LM Hash',
                confidence: 'medium',
                details: '16-character uppercase hexadecimal, likely LM hash'
            });
        }

        // SHA224 (56 hex characters)
        if (/^[a-f0-9]{56}$/i.test(input)) {
            hashDetections.push({
                type: 'SHA224 Hash',
                confidence: 'high',
                details: '56-character hexadecimal string matching SHA224 format'
            });
        }

        // SHA384 (96 hex characters)
        if (/^[a-f0-9]{96}$/i.test(input)) {
            hashDetections.push({
                type: 'SHA384 Hash',
                confidence: 'high',
                details: '96-character hexadecimal string matching SHA384 format'
            });
        }

        // RIPEMD-160 (40 hex characters)
        if (/^[a-f0-9]{40}$/i.test(input)) {
            hashDetections.push({
                type: 'RIPEMD-160 Hash',
                confidence: 'medium',
                details: '40-character hexadecimal string, could be RIPEMD-160 or SHA1'
            });
        }

        // Whirlpool (128 hex characters)
        if (/^[a-f0-9]{128}$/i.test(input)) {
            hashDetections.push({
                type: 'Whirlpool Hash',
                confidence: 'medium',
                details: '128-character hexadecimal string, could be Whirlpool or SHA512'
            });
        }

        // Tiger (48 hex characters)
        if (/^[a-f0-9]{48}$/i.test(input)) {
            hashDetections.push({
                type: 'Tiger Hash',
                confidence: 'medium',
                details: '48-character hexadecimal string, likely Tiger hash'
            });
        }

        // Snefru (64 or 128 hex characters)
        if (/^[a-f0-9]{64}$/i.test(input) || /^[a-f0-9]{128}$/i.test(input)) {
            hashDetections.push({
                type: 'Snefru Hash',
                confidence: 'low',
                details: '64 or 128-character hexadecimal string, could be Snefru hash'
            });
        }

        // Generic hex hash detection for common lengths
        if (/^[a-f0-9]+$/i.test(input)) {
            const length = input.length;
            if (length === 8) {
                hashDetections.push({
                    type: 'Short Hex Hash',
                    confidence: 'low',
                    details: '8-character hex string (could be CRC32 or similar)'
                });
            } else if (length === 16) {
                hashDetections.push({
                    type: 'Medium Hex Hash',
                    confidence: 'low',
                    details: '16-character hex string (could be MD4, LM hash, or similar)'
                });
            } else if (length === 24) {
                hashDetections.push({
                    type: '24-char Hex Hash',
                    confidence: 'low',
                    details: '24-character hex string (uncommon hash length)'
                });
            } else if (length === 48) {
                hashDetections.push({
                    type: '48-char Hex Hash',
                    confidence: 'low',
                    details: '48-character hex string (could be Tiger hash)'
                });
            } else if (length === 56) {
                hashDetections.push({
                    type: '56-char Hex Hash',
                    confidence: 'low',
                    details: '56-character hex string (could be SHA224)'
                });
            } else if (length === 96) {
                hashDetections.push({
                    type: '96-char Hex Hash',
                    confidence: 'low',
                    details: '96-character hex string (could be SHA384)'
                });
            } else if (length === 128) {
                hashDetections.push({
                    type: '128-char Hex Hash',
                    confidence: 'low',
                    details: '128-character hex string (could be SHA512, Whirlpool, or Snefru)'
                });
            } else if (length > 128) {
                hashDetections.push({
                    type: 'Very Long Hex Hash',
                    confidence: 'low',
                    details: `${length}-character hex string (very long, possibly custom hash)`
                });
            }
        }

        return hashDetections;
    }

    detectEncryption(input) {
        const encryptionDetections = [];

        // Base64 encoding
        if (/^[A-Za-z0-9+/]*={0,2}$/.test(input) && input.length % 4 === 0 && input.length > 0) {
            try {
                const decoded = atob(input);
                if (this.isValidBase64(input)) {
                    encryptionDetections.push({
                        type: 'Base64 Encoded',
                        confidence: 'high',
                        details: `Decodes to: "${decoded.substring(0, 50)}${decoded.length > 50 ? '...' : ''}"`
                    });
                }
            } catch (e) {
                // Not valid base64
            }
        }

        // Hex encoding
        if (/^[0-9a-fA-F]+$/.test(input) && input.length % 2 === 0) {
            try {
                const decoded = this.hexToString(input);
                if (decoded.length > 0) {
                    encryptionDetections.push({
                        type: 'Hex Encoded',
                        confidence: 'high',
                        details: `Decodes to: "${decoded.substring(0, 50)}${decoded.length > 50 ? '...' : ''}"`
                    });
                }
            } catch (e) {
                // Not valid hex
            }
        }

        // AES encrypted (common patterns)
        if (input.startsWith('U2FsdGVkX1') || input.includes('Salted__')) {
            encryptionDetections.push({
                type: 'AES Encrypted (OpenSSL)',
                confidence: 'high',
                details: 'OpenSSL AES encrypted data with salt'
            });
        }

        // JWT Token
        if (/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/.test(input)) {
            encryptionDetections.push({
                type: 'JWT Token',
                confidence: 'high',
                details: 'JSON Web Token with header.payload.signature structure'
            });
        }

        // Fernet encryption
        if (/^gAAAAAB[A-Za-z0-9+/]{40}={0,2}$/.test(input)) {
            encryptionDetections.push({
                type: 'Fernet Encrypted',
                confidence: 'high',
                details: 'Fernet symmetric encryption format'
            });
        }

        // GPG/PGP encrypted
        if (input.startsWith('-----BEGIN PGP MESSAGE-----') || input.startsWith('-----BEGIN PGP SIGNED MESSAGE-----')) {
            encryptionDetections.push({
                type: 'GPG/PGP Encrypted',
                confidence: 'high',
                details: 'GPG or PGP encrypted message'
            });
        }

		return encryptionDetections;
    }

	// Unique: Detect blockchain/crypto ecosystem identifiers
	detectBlockchain(input) {
		const results = [];
		const btcRegex = /^(bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{14,74}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/;
		const ethRegex = /^0x[a-fA-F0-9]{40}$/;
		const ipfsCidV0 = /^Qm[1-9A-HJ-NP-Za-km-z]{44}$/;
		const ipfsCidV1 = /^(baf|baef|bag[aq]|bafy)[A-Za-z2-7]+=*$/;

		if (btcRegex.test(input)) {
			results.push({ type: 'Bitcoin Address', confidence: 'medium', details: 'Valid-looking Bitcoin address (legacy or bech32)'});
		}
		if (ethRegex.test(input)) {
			results.push({ type: 'Ethereum Address', confidence: 'high', details: 'Valid-looking Ethereum address (0x-prefixed 40 hex)'});
		}
		if (ipfsCidV0.test(input) || ipfsCidV1.test(input)) {
			results.push({ type: 'IPFS CID', confidence: 'high', details: 'InterPlanetary File System content identifier'});
		}

		return results;
	}

    detectGeneralPatterns(input) {
        const patternDetections = [];

        // Random string analysis
        const entropy = this.calculateEntropy(input);
        if (entropy > 4.5) {
            patternDetections.push({
                type: 'High Entropy String',
                confidence: 'medium',
                details: `Entropy: ${entropy.toFixed(2)} (high randomness suggests hash or encrypted data)`
            });
        } else if (entropy > 3.0) {
            patternDetections.push({
                type: 'Medium Entropy String',
                confidence: 'low',
                details: `Entropy: ${entropy.toFixed(2)} (moderate randomness)`
            });
        }

        // Length analysis - expanded ranges
        if (input.length >= 16 && input.length <= 128) {
            if (input.length === 32) {
                patternDetections.push({
                    type: 'Hash-like Length',
                    confidence: 'medium',
                    details: `Length: ${input.length} characters (common for MD5, NTLM hashes)`
                });
            } else if (input.length === 40) {
                patternDetections.push({
                    type: 'Hash-like Length',
                    confidence: 'medium',
                    details: `Length: ${input.length} characters (common for SHA1 hashes)`
                });
            } else if (input.length === 64) {
                patternDetections.push({
                    type: 'Hash-like Length',
                    confidence: 'medium',
                    details: `Length: ${input.length} characters (common for SHA256 hashes)`
                });
            } else if (input.length >= 32 && input.length <= 64) {
                patternDetections.push({
                    type: 'Hash-like Length',
                    confidence: 'low',
                    details: `Length: ${input.length} characters (typical for many hash functions)`
                });
            } else if (input.length >= 80 && input.length <= 128) {
                patternDetections.push({
                    type: 'Long Hash-like Length',
                    confidence: 'low',
                    details: `Length: ${input.length} characters (could be SHA512 or other long hashes)`
                });
            }
        }

        // Character distribution analysis
        const charTypes = this.analyzeCharacterTypes(input);
        if (charTypes.hexOnly) {
            patternDetections.push({
                type: 'Hexadecimal Characters Only',
                confidence: 'medium',
                details: 'Contains only 0-9 and A-F characters (common in hashes)'
            });
        }

        if (charTypes.base64Like) {
            patternDetections.push({
                type: 'Base64-like Characters',
                confidence: 'low',
                details: 'Contains characters typical of Base64 encoding'
            });
        }

        // Additional pattern analysis
        if (input.length > 0) {
            const alphaCount = (input.match(/[a-zA-Z]/g) || []).length;
            const digitCount = (input.match(/[0-9]/g) || []).length;
            const specialCount = input.length - alphaCount - digitCount;
            
            if (alphaCount === 0 && digitCount > 0 && specialCount === 0) {
                patternDetections.push({
                    type: 'Numeric Only',
                    confidence: 'low',
                    details: 'Contains only digits (unusual for hashes/encryption)'
                });
            } else if (alphaCount > 0 && digitCount === 0 && specialCount === 0) {
                patternDetections.push({
                    type: 'Alphabetic Only',
                    confidence: 'low',
                    details: 'Contains only letters (unusual for hashes/encryption)'
                });
            } else if (specialCount > input.length * 0.3) {
                patternDetections.push({
                    type: 'High Special Character Ratio',
                    confidence: 'low',
                    details: `High ratio of special characters (${((specialCount/input.length)*100).toFixed(1)}%)`
                });
            }
        }

        // Check for common hash prefixes
        if (input.startsWith('$')) {
            patternDetections.push({
                type: 'Hash Prefix Detected',
                confidence: 'medium',
                details: 'Starts with $ (common in many hash formats)'
            });
        }

        // Check for common encryption prefixes
        if (input.startsWith('-----BEGIN') || input.startsWith('-----END')) {
            patternDetections.push({
                type: 'PEM-like Format',
                confidence: 'medium',
                details: 'Contains PEM-like headers (common in encrypted/encoded data)'
            });
        }

        return patternDetections;
    }

    determineOverallResult(detections) {
        const hashDetections = detections.filter(d => d.type.includes('Hash'));
        const encryptionDetections = detections.filter(d => d.type.includes('Encoded') || d.type.includes('Encrypted') || d.type.includes('Token'));
        const patternDetections = detections.filter(d => !d.type.includes('Hash') && !d.type.includes('Encoded') && !d.type.includes('Encrypted') && !d.type.includes('Token'));

        // High confidence hash detection
        if (hashDetections.length > 0 && hashDetections.some(d => d.confidence === 'high')) {
            return {
                type: 'hash',
                message: 'This appears to be a password hash',
                confidence: 'high'
            };
        }

        // High confidence encryption detection
        if (encryptionDetections.length > 0 && encryptionDetections.some(d => d.confidence === 'high')) {
            return {
                type: 'encryption',
                message: 'This appears to be encrypted or encoded data',
                confidence: 'high'
            };
        }

        // Medium confidence hash detection
        if (hashDetections.length > 0) {
            return {
                type: 'hash',
                message: 'This might be a password hash',
                confidence: 'medium'
            };
        }

        // Medium confidence encryption detection
        if (encryptionDetections.length > 0) {
            return {
                type: 'encryption',
                message: 'This might be encrypted or encoded data',
                confidence: 'medium'
            };
        }

        // Analyze patterns to make educated guesses
        const highEntropy = patternDetections.some(d => d.type === 'High Entropy String');
        const mediumEntropy = patternDetections.some(d => d.type === 'Medium Entropy String');
        const hexOnly = patternDetections.some(d => d.type === 'Hexadecimal Characters Only');
        const hashLikeLength = patternDetections.some(d => d.type === 'Hash-like Length' || d.type === 'Long Hash-like Length');
        const base64Like = patternDetections.some(d => d.type === 'Base64-like Characters');
        const hashPrefix = patternDetections.some(d => d.type === 'Hash Prefix Detected');
        const pemLike = patternDetections.some(d => d.type === 'PEM-like Format');
        const numericOnly = patternDetections.some(d => d.type === 'Numeric Only');
        const alphabeticOnly = patternDetections.some(d => d.type === 'Alphabetic Only');

        // High confidence pattern combinations
        if (highEntropy && (hexOnly || hashLikeLength)) {
            return {
                type: 'hash',
                message: 'This appears to be a hash (high entropy + hex characters)',
                confidence: 'medium'
            };
        }

        if (highEntropy && base64Like) {
            return {
                type: 'encryption',
                message: 'This appears to be encrypted data (high entropy + base64-like)',
                confidence: 'medium'
            };
        }

        if (hashPrefix && (highEntropy || mediumEntropy)) {
            return {
                type: 'hash',
                message: 'This appears to be a hash (hash prefix + entropy)',
                confidence: 'medium'
            };
        }

        if (pemLike) {
            return {
                type: 'encryption',
                message: 'This appears to be encrypted/encoded data (PEM format)',
                confidence: 'medium'
            };
        }

        // Medium confidence pattern combinations
        if (hexOnly && hashLikeLength) {
            return {
                type: 'hash',
                message: 'This might be a hash (hex characters + typical length)',
                confidence: 'low'
            };
        }

        if (mediumEntropy && (hexOnly || base64Like)) {
            return {
                type: 'unknown',
                message: 'This might be encoded data (moderate entropy + encoding patterns)',
                confidence: 'low'
            };
        }

        // Low confidence but still useful analysis
        if (highEntropy) {
            return {
                type: 'unknown',
                message: 'This appears to be random data (could be hash or encrypted)',
                confidence: 'low'
            };
        }

        if (numericOnly) {
            return {
                type: 'unknown',
                message: 'This appears to be numeric data (unlikely to be hash/encryption)',
                confidence: 'low'
            };
        }

        if (alphabeticOnly) {
            return {
                type: 'unknown',
                message: 'This appears to be alphabetic data (unlikely to be hash/encryption)',
                confidence: 'low'
            };
        }

        if (patternDetections.length > 0) {
            return {
                type: 'unknown',
                message: 'This might be encoded or hashed data (patterns detected)',
                confidence: 'low'
            };
        }

        return {
            type: 'unknown',
            message: 'Unable to determine if this is a hash or encrypted data',
            confidence: 'low'
        };
    }

	displayResults(results) {
		// Advanced UI nodes
		const resultsSection = document.getElementById('resultsSection');
		const primaryContent = document.getElementById('primaryContent');
		const primaryConfidence = document.getElementById('primaryConfidence');
		const neuralPatterns = document.getElementById('neuralPatterns');
		const fingerprintVisual = document.getElementById('fingerprintVisual');
		const statsCharts = document.getElementById('statsCharts');
		const blockchainResults = document.getElementById('blockchainResults');
		const transformResults = document.getElementById('transformResults');
		const overallConfidence = document.getElementById('overallConfidence');

		// Legacy fallback
		const legacyCard = document.getElementById('resultCard');

		// Confidence meter
		this.updateConfidenceMeter(results.confidence.overallPercent);
		if (overallConfidence) overallConfidence.textContent = `${Math.round(results.confidence.overallPercent)}%`;

		// Primary classification
		if (primaryContent && primaryConfidence) {
			const icon = results.overallResult.type === 'hash' ? '🔏' : results.overallResult.type === 'encryption' ? '🔐' : '🧪';
			primaryContent.innerHTML = `
				<div class="classification-result">
					<div class="result-icon">${icon}</div>
					<div class="result-text">${results.overallResult.message} (confidence: ${results.overallResult.confidence})</div>
				</div>
			`;
			primaryConfidence.className = `confidence-indicator ${results.overallResult.confidence}`;

			// Narrative inside primary card (typewriter effect)
			const narrativeEl = document.getElementById('resultNarrative');
			if (narrativeEl && results.narrative?.primary) {
				this.typeInto(narrativeEl, results.narrative.primary, 18);
			}
		}

		// Neural signals
		if (neuralPatterns) {
			const topSignals = results.confidence.signals.slice(0, 6)
				.map(s => `<div>• ${s.label}: <strong>${(s.score*100).toFixed(0)}%</strong></div>`)
				.join('');
			neuralPatterns.innerHTML = topSignals || 'No significant neural signals detected.';
		}

		// Fingerprint visualization
		if (fingerprintVisual) {
			const fp = this.buildFingerprint(results.input);
			fingerprintVisual.innerHTML = fp.map(v => `<span style="display:inline-block;width:6px;height:16px;margin:0 1px;background:rgba(0,255,255,${v});"></span>`).join('');
		}

		// Stats
		if (statsCharts) {
			const entropy = this.calculateEntropy(results.input).toFixed(2);
			const length = results.input.length;
			const types = this.analyzeCharacterTypes(results.input);
			statsCharts.innerHTML = `
				<div>Entropy: <strong>${entropy}</strong></div>
				<div>Length: <strong>${length}</strong></div>
				<div>Hex-only: <strong>${types.hexOnly}</strong> | Base64-like: <strong>${types.base64Like}</strong></div>
			`;
		}

		// Human-friendly explanation card
		const explain = document.getElementById('resultExplanationContent');
		const explainDot = document.getElementById('explainConfidence');
		if (explain && results.narrative?.explainer) {
			explain.innerHTML = '';
			this.typeInto(explain, results.narrative.explainer, 22);
		}
		if (explainDot) explainDot.className = `confidence-indicator ${results.overallResult.confidence}`;

		// Blockchain section
		if (blockchainResults) {
			const chainFindings = results.detections.filter(d => /(Bitcoin|Ethereum|IPFS)/.test(d.type));
			blockchainResults.innerHTML = chainFindings.length
				? chainFindings.map(d => `<div class="detection-item"><div><div class="detection-type">${d.type}</div><div class="details">${d.details}</div></div><div class="confidence ${d.confidence}">${d.confidence}</div></div>`).join('')
				: 'No blockchain/crypto identifiers detected.';
		}

		// Transformations
		if (transformResults) {
			const attempts = [];
			try {
				if (this.isValidBase64(results.input)) {
					const dec = atob(results.input);
					attempts.push(`<div><strong>Base64 → UTF-8:</strong> ${this.escapeHtml(dec).slice(0,180)}</div>`);
				}
			} catch {}
			try {
				if (/^[0-9a-fA-F]+$/.test(results.input) && results.input.length % 2 === 0) {
					const dec = this.hexToString(results.input);
					if (dec) attempts.push(`<div><strong>Hex → ASCII:</strong> ${this.escapeHtml(dec).slice(0,180)}</div>`);
				}
			} catch {}
			transformResults.innerHTML = attempts.join('') || 'No safe transformations available for this input.';
		}

		if (resultsSection) resultsSection.style.display = 'block';

		// Legacy fallback
		if (legacyCard && !primaryContent) {
			let html = `
				<div class="overall-result ${results.overallResult.type}">
					<strong>${results.overallResult.message}</strong><br>
					<small>Confidence: ${results.overallResult.confidence}</small>
				</div>
			`;
			if (results.detections.length > 0) {
				html += '<h3>Detailed Analysis:</h3>';
				results.detections.forEach(detection => {
					html += `
						<div class="detection-item">
							<div>
								<div class="detection-type">${detection.type}</div>
								<div class="details">${detection.details}</div>
							</div>
							<div class="confidence ${detection.confidence}">${detection.confidence}</div>
						</div>
					`;
				});
			} else {
				html += '<p>No specific patterns detected.</p>';
			}
			legacyCard.innerHTML = html;
		}
	}

    // Utility functions
    isValidBase64(str) {
        try {
            return btoa(atob(str)) === str;
        } catch (err) {
            return false;
        }
    }
	buildNarrative({ input, detections, overall, confidence }) {
		const top = detections.slice(0, 3).map(d => d.type).join(', ') || 'no strong patterns';
		const len = input.length;
		const entropy = this.calculateEntropy(input).toFixed(2);
		const flavor = overall.type === 'hash' ? 'fingerprint-like signature' : overall.type === 'encryption' ? 'sealed envelope of data' : 'mysterious string';
		const primary = `We see a ${this.wrapHighlight(flavor)} with length ${this.wrapHighlight(len)} and entropy ${this.wrapHighlight(entropy)}. Signals suggest: ${this.wrapHighlight(top)}.`;
		const explainer = `${overall.message}. Based on our neural-style scoring (${confidence.overallPercent}%), we combined entropy, length, and character distribution to form this conclusion. If this is Base64 or Hex, try decoding below in the Transformation Lab. If it’s a hash, note that hashes are one-way and cannot be decrypted.`;
		return { primary, explainer };
	}

	wrapHighlight(text) {
		return `<span class="narrative-highlight">${this.escapeHtml(String(text))}</span>`;
	}

	async typeInto(el, text, cps = 16) {
		// cps: characters per second
		el.classList.remove('typewriter');
		el.innerHTML = '';
		await new Promise(r => setTimeout(r, 25));
		el.classList.add('typewriter');
		for (let i = 0; i <= text.length; i++) {
			el.innerHTML = text.slice(0, i);
			await new Promise(r => setTimeout(r, Math.max(8, 1000 / cps)));
		}
		el.classList.remove('typewriter');
	}

	escapeHtml(str) {
		return str
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;')
			.replace(/"/g, '&quot;')
			.replace(/'/g, '&#039;');
	}

    hexToString(hex) {
        let result = '';
        for (let i = 0; i < hex.length; i += 2) {
            const hexByte = hex.substr(i, 2);
            const charCode = parseInt(hexByte, 16);
            if (charCode >= 32 && charCode <= 126) { // Printable ASCII
                result += String.fromCharCode(charCode);
            }
        }
        return result;
    }

    calculateEntropy(str) {
        const freq = {};
        for (let char of str) {
            freq[char] = (freq[char] || 0) + 1;
        }
        
        let entropy = 0;
        const len = str.length;
        for (let count of Object.values(freq)) {
            const p = count / len;
            entropy -= p * Math.log2(p);
        }
        
        return entropy;
    }

    analyzeCharacterTypes(str) {
        const hexRegex = /^[0-9a-fA-F]+$/;
        const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
        
        return {
            hexOnly: hexRegex.test(str),
            base64Like: base64Regex.test(str) && str.length > 0
        };
    }

	// Unique: pseudo-neural confidence scoring
	computeConfidenceScore(detections, input) {
		const signals = [];
		const hasHighHash = detections.some(d => d.type.includes('Hash') && d.confidence === 'high');
		const hasHighEnc = detections.some(d => (d.type.includes('Encrypted') || d.type.includes('Encoded') || d.type.includes('Token')) && d.confidence === 'high');
		const entropy = this.calculateEntropy(input);
		const len = input.length;
		const types = this.analyzeCharacterTypes(input);

		signals.push({ label: 'Entropy', score: Math.min(entropy / 6, 1) });
		signals.push({ label: 'Length-typical', score: [32,40,56,64,96,128].includes(len) ? 1 : (len >= 24 && len <= 132 ? 0.5 : 0.1) });
		signals.push({ label: 'Hex-only', score: types.hexOnly ? 0.8 : 0 });
		signals.push({ label: 'Base64-like', score: types.base64Like ? 0.6 : 0 });
		signals.push({ label: 'High hash match', score: hasHighHash ? 1 : 0 });
		signals.push({ label: 'High encryption match', score: hasHighEnc ? 1 : 0 });

		const weighted = signals.map(s => s.score);
		const overall = weighted.reduce((a,b)=>a+b,0) / Math.max(signals.length,1);
		return { overallPercent: Math.max(5, Math.min(100, Math.round(overall * 100))), signals };
	}

	updateConfidenceMeter(percent) {
		const meter = document.getElementById('confidenceMeter');
		const value = document.getElementById('confidenceValue');
		if (meter) meter.style.width = `${Math.round(percent)}%`;
		if (value) value.textContent = `${Math.round(percent)}%`;
	}

	updateRealtimePanels(value) {
		const neuralOutput = document.getElementById('neuralOutput');
		const statsDisplay = document.getElementById('statsDisplay');
		const cryptoSignature = document.getElementById('cryptoSignature');

		if (statsDisplay) {
			const entropy = value ? this.calculateEntropy(value).toFixed(2) : '0.00';
			statsDisplay.textContent = `len=${value.length}, entropy=${entropy}`;
		}
		if (neuralOutput) {
			if (!value) neuralOutput.textContent = 'Ready for analysis...';
			else neuralOutput.textContent = value.length > 0 ? 'Pattern forming… analyzing signals.' : 'Ready for analysis...';
		}
		if (cryptoSignature) {
			if (!value) cryptoSignature.textContent = 'No signature detected';
			else cryptoSignature.textContent = /^[A-F0-9]{32}$/.test(value) ? 'NTLM-like signature' : 'No obvious signature';
		}
	}

	buildFingerprint(str) {
		const buckets = new Array(32).fill(0);
		for (let i = 0; i < str.length; i++) {
			const code = str.charCodeAt(i);
			buckets[i % buckets.length] = (buckets[i % buckets.length] * 0.7) + ((code % 97) / 97) * 0.3;
		}
		return buckets.map(v => Math.max(0.1, Math.min(1, v)));
	}

	deepScan() {
		const input = document.getElementById('inputString')?.value.trim() || '';
		if (!input) return;
		const results = this.performAnalysis(input);
		results.confidence.overallPercent = Math.min(100, results.confidence.overallPercent + 5);
		this.displayResults(results);
	}

	openCompare() {
		const current = document.getElementById('inputString')?.value.trim() || '';
		const other = prompt('Enter another string to compare patterns against:');
		if (other == null) return;
		const a = this.performAnalysis(current);
		const b = this.performAnalysis(other.trim());
		const msg = `A: len=${current.length}, entropy=${this.calculateEntropy(current).toFixed(2)} | ` +
					`B: len=${other.trim().length}, entropy=${this.calculateEntropy(other.trim()).toFixed(2)}`;
		alert(`Comparison summary:\n${msg}`);
	}
}

// Initialize the analyzer when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new StringAnalyzer();
});
