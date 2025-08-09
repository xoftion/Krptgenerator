// Enhanced Key Generator Application
class KeyGenerator {
    constructor() {
        this.keyTypes = {};
        this.initializeElements();
        this.bindEvents();
        this.loadKeyTypes();
        this.loadHistory();
        this.updateKeyTypeOptions();
    }

    initializeElements() {
        this.form = document.getElementById('keyGeneratorForm');
        this.keyTypeSelect = document.getElementById('keyType');
        this.keySizeSelect = document.getElementById('keySize');
        this.keyFormatSelect = document.getElementById('keyFormat');
        this.passwordInput = document.getElementById('password');
        this.passwordGroup = document.getElementById('passwordGroup');
        this.togglePasswordBtn = document.getElementById('togglePassword');
        this.validateKeyBtn = document.getElementById('validateKeyBtn');
        this.keyOutput = document.getElementById('keyOutput');
        this.keyHistory = document.getElementById('keyHistory');
        this.keyInfoCard = document.getElementById('keyInfoCard');
        this.keyInfo = document.getElementById('keyInfo');
        this.clearOutputBtn = document.getElementById('clearOutputBtn');
        this.clearHistoryBtn = document.getElementById('clearHistoryBtn');
        this.copyToast = new bootstrap.Toast(document.getElementById('copyToast'));
    }

    bindEvents() {
        this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        this.keyTypeSelect.addEventListener('change', () => this.updateKeyTypeOptions());
        this.togglePasswordBtn.addEventListener('click', () => this.togglePasswordVisibility());
        this.validateKeyBtn.addEventListener('click', () => this.showValidationModal());
        this.clearOutputBtn.addEventListener('click', () => this.clearOutput());
        this.clearHistoryBtn.addEventListener('click', () => this.clearHistory());
    }

    async loadKeyTypes() {
        try {
            const response = await fetch('/api/key_types');
            this.keyTypes = await response.json();
        } catch (error) {
            console.error('Failed to load key types:', error);
        }
    }

    togglePasswordVisibility() {
        const type = this.passwordInput.type === 'password' ? 'text' : 'password';
        this.passwordInput.type = type;
        
        const icon = this.togglePasswordBtn.querySelector('i');
        icon.className = type === 'password' ? 'fas fa-eye' : 'fas fa-eye-slash';
    }

    updateKeyTypeOptions() {
        const keyType = this.keyTypeSelect.value;
        const keySizeGroup = document.getElementById('keySizeGroup');
        const keyFormatGroup = document.getElementById('keyFormatGroup');

        // Show/hide password field for key derivation functions
        if (['pbkdf2', 'scrypt'].includes(keyType)) {
            this.passwordGroup.style.display = 'block';
        } else {
            this.passwordGroup.style.display = 'none';
        }

        // Use loaded key types data if available, otherwise fallback to defaults
        const keyTypeConfig = this.keyTypes[keyType];
        
        if (keyTypeConfig) {
            // Update key size options
            this.keySizeSelect.innerHTML = '';
            if (keyTypeConfig.sizes.length > 1) {
                keySizeGroup.style.display = 'block';
                keyTypeConfig.sizes.forEach(size => {
                    this.keySizeSelect.innerHTML += `<option value="${size}">${size}</option>`;
                });
            } else {
                keySizeGroup.style.display = 'none';
            }

            // Update format options
            this.keyFormatSelect.innerHTML = '';
            if (keyTypeConfig.formats && keyTypeConfig.formats.length > 0) {
                keyFormatGroup.style.display = 'block';
                keyTypeConfig.formats.forEach(format => {
                    const formatName = this.getFormatDisplayName(format);
                    this.keyFormatSelect.innerHTML += `<option value="${format}">${formatName}</option>`;
                });
            } else {
                keyFormatGroup.style.display = 'none';
            }
        } else {
            // Fallback to original logic
            this.updateKeyTypeOptionsFallback(keyType, keySizeGroup, keyFormatGroup);
        }
    }

    getFormatDisplayName(format) {
        const formatNames = {
            'base64': 'Base64 (Standard)',
            'hex': 'Hexadecimal',
            'raw': 'Raw Bytes',
            'pem': 'PEM Format',
            'der': 'DER Format',
            'jwt': 'JWT Base64URL'
        };
        return formatNames[format] || format.toUpperCase();
    }

    updateKeyTypeOptionsFallback(keyType, keySizeGroup, keyFormatGroup) {
        this.keySizeSelect.innerHTML = '';
        
        if (keyType === 'fernet') {
            keySizeGroup.style.display = 'none';
            keyFormatGroup.style.display = 'block';
        } else if (keyType === 'aes') {
            keySizeGroup.style.display = 'block';
            keyFormatGroup.style.display = 'block';
            this.keySizeSelect.innerHTML = `
                <option value="128">128</option>
                <option value="192">192</option>
                <option value="256">256</option>
            `;
        } else if (['rsa', 'ed25519', 'ecdsa'].includes(keyType)) {
            keySizeGroup.style.display = 'block';
            keyFormatGroup.style.display = 'block';
            if (keyType === 'rsa') {
                this.keySizeSelect.innerHTML = `
                    <option value="2048">2048</option>
                    <option value="3072">3072</option>
                    <option value="4096">4096</option>
                `;
            } else if (keyType === 'ecdsa') {
                this.keySizeSelect.innerHTML = `
                    <option value="256">256</option>
                    <option value="384">384</option>
                    <option value="521">521</option>
                `;
            } else {
                this.keySizeSelect.innerHTML = `<option value="256">256</option>`;
            }
        } else if (['pbkdf2', 'scrypt', 'hkdf', 'hmac', 'random'].includes(keyType)) {
            keySizeGroup.style.display = 'block';
            keyFormatGroup.style.display = 'block';
            this.keySizeSelect.innerHTML = `
                <option value="128">128</option>
                <option value="256">256</option>
                <option value="512">512</option>
                <option value="1024">1024</option>
            `;
        }
    }

    async handleSubmit(e) {
        e.preventDefault();
        
        const submitBtn = this.form.querySelector('button[type="submit"]');
        const originalText = submitBtn.innerHTML;
        
        try {
            // Show loading state
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Generating...';
            submitBtn.disabled = true;

            const formData = {
                type: this.keyTypeSelect.value,
                format: this.keyFormatSelect.value,
                size: this.keySizeSelect.value
            };

            // Add password for derivation functions
            if (['pbkdf2', 'scrypt'].includes(this.keyTypeSelect.value)) {
                formData.password = this.passwordInput.value || 'default_password';
            }

            const response = await fetch('/generate_key', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(formData)
            });

            const result = await response.json();

            if (result.success) {
                this.displayKey(result);
                this.loadHistory();
            } else {
                this.showError(result.error);
            }

        } catch (error) {
            this.showError('Failed to generate key: ' + error.message);
        } finally {
            // Reset button
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
        }
    }

    showValidationModal() {
        // Create validation modal if it doesn't exist
        let modal = document.getElementById('validationModal');
        if (!modal) {
            modal = this.createValidationModal();
            document.body.appendChild(modal);
        }
        
        const bootstrapModal = new bootstrap.Modal(modal);
        bootstrapModal.show();
    }

    createValidationModal() {
        const modalHtml = `
            <div class="modal fade" id="validationModal" tabindex="-1">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">
                                <i class="fas fa-shield-alt me-2"></i>
                                Key Validation
                            </h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <form id="validateForm">
                                <div class="mb-3">
                                    <label for="validateKeyType" class="form-label">Key Type</label>
                                    <select class="form-select" id="validateKeyType" required>
                                        <option value="fernet">Fernet</option>
                                        <option value="aes">AES</option>
                                        <option value="rsa">RSA</option>
                                        <option value="random">Random</option>
                                    </select>
                                </div>
                                <div class="mb-3">
                                    <label for="validateKeyValue" class="form-label">Key Value</label>
                                    <textarea class="form-control" id="validateKeyValue" rows="4" 
                                              placeholder="Paste your key here..." required></textarea>
                                </div>
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-check me-2"></i>
                                    Validate Key
                                </button>
                            </form>
                            <div id="validationResult" class="mt-4" style="display: none;"></div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        const div = document.createElement('div');
        div.innerHTML = modalHtml;
        const modal = div.firstElementChild;
        
        // Bind validation form submit
        modal.querySelector('#validateForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.validateKey();
        });
        
        return modal;
    }

    async validateKey() {
        const keyType = document.getElementById('validateKeyType').value;
        const keyValue = document.getElementById('validateKeyValue').value.trim();
        const resultDiv = document.getElementById('validationResult');
        
        if (!keyValue) {
            resultDiv.innerHTML = `
                <div class="alert alert-warning">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    Please enter a key value to validate.
                </div>
            `;
            resultDiv.style.display = 'block';
            return;
        }

        try {
            const response = await fetch('/api/validate_key', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    key: keyValue,
                    type: keyType
                })
            });

            const result = await response.json();
            
            if (response.ok) {
                this.displayValidationResult(result);
            } else {
                this.showValidationError(result.error);
            }
        } catch (error) {
            this.showValidationError('Validation failed: ' + error.message);
        }
    }

    displayValidationResult(result) {
        const resultDiv = document.getElementById('validationResult');
        const statusClass = result.valid ? 'success' : 'danger';
        const statusIcon = result.valid ? 'check-circle' : 'times-circle';
        
        resultDiv.innerHTML = `
            <div class="alert alert-${statusClass}">
                <h6><i class="fas fa-${statusIcon} me-2"></i>Validation Result</h6>
                <div class="row mt-3">
                    <div class="col-md-6">
                        <strong>Valid:</strong> ${result.valid ? 'Yes' : 'No'}<br>
                        <strong>Length:</strong> ${result.length} characters<br>
                        <strong>Format:</strong> ${result.format_detected}
                    </div>
                    <div class="col-md-6">
                        <strong>Entropy:</strong> ~${result.entropy_estimate} bits<br>
                        <strong>Security:</strong> ${result.security_level}
                    </div>
                </div>
                ${result.recommendations && result.recommendations.length > 0 ? `
                    <div class="mt-3">
                        <strong>Recommendations:</strong>
                        <ul class="mb-0 mt-1">
                            ${result.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
            </div>
        `;
        resultDiv.style.display = 'block';
    }

    showValidationError(error) {
        const resultDiv = document.getElementById('validationResult');
        resultDiv.innerHTML = `
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <strong>Error:</strong> ${error}
            </div>
        `;
        resultDiv.style.display = 'block';
    }

    displayKey(result) {
        if (result.private_key && result.public_key) {
            // Key pair (RSA, Ed25519, ECDSA)
            this.keyOutput.innerHTML = `
                <div class="key-container mb-4 fade-in">
                    <h6 class="text-success mb-3">
                        <i class="fas fa-lock me-2"></i>
                        Private Key
                    </h6>
                    <div class="position-relative">
                        <textarea class="form-control key-output bg-dark text-light" rows="10" readonly>${result.private_key.value}</textarea>
                        <button class="btn btn-sm btn-outline-light copy-btn" onclick="copyToClipboard('${result.private_key.value.replace(/'/g, "\\'")}')">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                </div>
                <div class="key-container fade-in">
                    <h6 class="text-info mb-3">
                        <i class="fas fa-unlock me-2"></i>
                        Public Key
                    </h6>
                    <div class="position-relative">
                        <textarea class="form-control key-output bg-dark text-light" rows="6" readonly>${result.public_key.value}</textarea>
                        <button class="btn btn-sm btn-outline-light copy-btn" onclick="copyToClipboard('${result.public_key.value.replace(/'/g, "\\'")}')">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                </div>
            `;
        } else if (result.key && result.salt) {
            // Key derivation function with salt
            this.keyOutput.innerHTML = `
                <div class="key-container mb-4 fade-in">
                    <h6 class="text-success mb-3">
                        <i class="fas fa-key me-2"></i>
                        Derived Key
                    </h6>
                    <div class="position-relative">
                        <textarea class="form-control key-output bg-dark text-light" rows="4" readonly>${result.key.value}</textarea>
                        <button class="btn btn-sm btn-outline-light copy-btn" onclick="copyToClipboard('${result.key.value.replace(/'/g, "\\'")}')">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                    <div class="mt-2 text-muted small">Format: ${result.key.format}</div>
                </div>
                <div class="key-container fade-in">
                    <h6 class="text-warning mb-3">
                        <i class="fas fa-random me-2"></i>
                        Salt (Store separately!)
                    </h6>
                    <div class="position-relative">
                        <textarea class="form-control key-output bg-dark text-light" rows="2" readonly>${result.salt.value}</textarea>
                        <button class="btn btn-sm btn-outline-light copy-btn" onclick="copyToClipboard('${result.salt.value.replace(/'/g, "\\'")}')">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                    <div class="mt-2 text-muted small">Format: ${result.salt.format}</div>
                </div>
            `;
        } else {
            // Single key
            const rows = result.key.value.length > 200 ? 6 : 4;
            this.keyOutput.innerHTML = `
                <div class="key-container fade-in">
                    <div class="position-relative">
                        <textarea class="form-control key-output bg-dark text-light" rows="${rows}" readonly>${result.key.value}</textarea>
                        <button class="btn btn-sm btn-outline-light copy-btn" onclick="copyToClipboard('${result.key.value.replace(/'/g, "\\'")}')">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                    <div class="mt-2 text-muted small">
                        Format: ${result.key.format}
                    </div>
                </div>
            `;
        }

        // Enhanced key information display
        const securityColor = this.getSecurityLevelColor(result.info.security_level);
        const useCases = result.info.use_cases || [];
        const recommendations = result.info.recommendations || [];

        this.keyInfo.innerHTML = `
            <div class="row">
                <div class="col-md-4">
                    <strong>Type:</strong><br>
                    <span class="text-primary">${result.info.type}</span>
                </div>
                <div class="col-md-4">
                    <strong>Size:</strong><br>
                    <span class="text-info">${result.info.size}</span>
                </div>
                <div class="col-md-4">
                    <strong>Security:</strong><br>
                    <span class="text-${securityColor}">${result.info.security_level || 'High'}</span>
                </div>
            </div>
            <div class="mt-3">
                <strong>Description:</strong><br>
                <span class="text-muted">${result.info.description}</span>
            </div>
            ${useCases.length > 0 ? `
                <div class="mt-3">
                    <strong>Common Use Cases:</strong><br>
                    <div class="d-flex flex-wrap gap-1 mt-1">
                        ${useCases.map(useCase => `<span class="badge bg-secondary">${useCase}</span>`).join('')}
                    </div>
                </div>
            ` : ''}
            ${recommendations.length > 0 ? `
                <div class="alert alert-warning mt-3">
                    <strong><i class="fas fa-exclamation-triangle me-2"></i>Security Recommendations:</strong>
                    <ul class="mb-0 mt-2">
                        ${recommendations.map(rec => `<li>${rec}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
        `;

        this.keyInfoCard.style.display = 'block';
        this.clearOutputBtn.style.display = 'inline-block';
    }

    getSecurityLevelColor(level) {
        switch (level?.toLowerCase()) {
            case 'high': return 'success';
            case 'medium': return 'warning';
            case 'low': return 'danger';
            default: return 'success';
        }
    }

    showError(message) {
        this.keyOutput.innerHTML = `
            <div class="alert alert-danger fade-in" role="alert">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <strong>Error:</strong> ${message}
            </div>
        `;
        this.keyInfoCard.style.display = 'none';
        this.clearOutputBtn.style.display = 'none';
    }

    clearOutput() {
        this.keyOutput.innerHTML = `
            <div class="text-muted text-center p-4">
                <i class="fas fa-arrow-left me-2"></i>
                Generate a key to see the output here
            </div>
        `;
        this.keyInfoCard.style.display = 'none';
        this.clearOutputBtn.style.display = 'none';
    }

    async loadHistory() {
        try {
            const response = await fetch('/get_history');
            const result = await response.json();
            
            if (result.history && result.history.length > 0) {
                this.keyHistory.innerHTML = result.history.map(item => `
                    <div class="history-item p-3 mb-3 border rounded fade-in">
                        <div class="row align-items-center">
                            <div class="col-md-8">
                                <div class="d-flex align-items-center mb-2">
                                    <span class="badge bg-primary me-2">${item.type}</span>
                                    <span class="badge bg-secondary me-2">${item.size}</span>
                                    <span class="badge bg-info">${item.format}</span>
                                </div>
                                <div class="key-output small text-muted" style="max-height: 60px; overflow: hidden;">
                                    ${item.value.substring(0, 100)}${item.value.length > 100 ? '...' : ''}
                                </div>
                            </div>
                            <div class="col-md-4 text-end">
                                <button class="btn btn-sm btn-outline-secondary" onclick="copyToClipboard('${item.value.replace(/'/g, "\\'")}')">
                                    <i class="fas fa-copy me-1"></i>
                                    Copy
                                </button>
                            </div>
                        </div>
                    </div>
                `).join('');
            } else {
                this.keyHistory.innerHTML = `
                    <div class="text-muted text-center p-4">
                        <i class="fas fa-clock me-2"></i>
                        No keys generated yet
                    </div>
                `;
            }
        } catch (error) {
            console.error('Failed to load history:', error);
        }
    }

    async clearHistory() {
        try {
            const response = await fetch('/clear_history', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            if (response.ok) {
                this.loadHistory();
            }
        } catch (error) {
            console.error('Failed to clear history:', error);
        }
    }
}

// Global function for copying to clipboard
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        
        // Show toast notification
        const toast = new bootstrap.Toast(document.getElementById('copyToast'));
        toast.show();
    } catch (error) {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        
        // Show toast notification
        const toast = new bootstrap.Toast(document.getElementById('copyToast'));
        toast.show();
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new KeyGenerator();
});
