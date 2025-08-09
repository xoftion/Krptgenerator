// Key Generator Application
class KeyGenerator {
    constructor() {
        this.initializeElements();
        this.bindEvents();
        this.loadHistory();
        this.updateKeyTypeOptions();
    }

    initializeElements() {
        this.form = document.getElementById('keyGeneratorForm');
        this.keyTypeSelect = document.getElementById('keyType');
        this.keySizeSelect = document.getElementById('keySize');
        this.keyFormatSelect = document.getElementById('keyFormat');
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
        this.clearOutputBtn.addEventListener('click', () => this.clearOutput());
        this.clearHistoryBtn.addEventListener('click', () => this.clearHistory());
    }

    updateKeyTypeOptions() {
        const keyType = this.keyTypeSelect.value;
        const keySizeGroup = document.getElementById('keySizeGroup');
        const keyFormatGroup = document.getElementById('keyFormatGroup');

        // Update key size options based on type
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
        } else if (keyType === 'rsa') {
            keySizeGroup.style.display = 'block';
            keyFormatGroup.style.display = 'none';
            this.keySizeSelect.innerHTML = `
                <option value="2048">2048</option>
                <option value="3072">3072</option>
                <option value="4096">4096</option>
            `;
        } else if (keyType === 'random') {
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

    displayKey(result) {
        if (result.private_key && result.public_key) {
            // RSA key pair
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
        } else {
            // Single key
            this.keyOutput.innerHTML = `
                <div class="key-container fade-in">
                    <div class="position-relative">
                        <textarea class="form-control key-output bg-dark text-light" rows="4" readonly>${result.key.value}</textarea>
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

        // Show key information
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
                    <span class="text-success">High</span>
                </div>
            </div>
            <div class="mt-3">
                <strong>Description:</strong><br>
                <span class="text-muted">${result.info.description}</span>
            </div>
        `;

        this.keyInfoCard.style.display = 'block';
        this.clearOutputBtn.style.display = 'inline-block';
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
