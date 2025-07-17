// Notes management system with persistent backend storage
class NotesManager {
    constructor() {
        this.currentUser = localStorage.getItem('username') || 'User';
        this.currentCategoryId = null;
        this.categories = [];
        this.commands = [];
        this.authToken = localStorage.getItem('authToken');

        this.init();
    }

    init() {
        // Check authentication
        if (!this.isLoggedIn()) {
            window.location.href = '/login';
            return;
        }

        this.setupEventListeners();
        this.loadDataFromServer();
        this.updateUserInfo();
    }

    isLoggedIn() {
        // Fix: Check for both null and empty string
        return this.authToken && this.authToken !== 'null' && this.authToken.trim() !== '';
    }

    getAuthHeaders() {
        return {
            'Authorization': `Bearer ${this.authToken}`,
            'Content-Type': 'application/json'
        };
    }

    async apiRequest(url, options = {}) {
        try {
            const response = await fetch(url, {
                ...options,
                headers: {
                    ...this.getAuthHeaders(),
                    ...options.headers
                }
            });

            if (response.status === 401) {
                // Token expired or invalid
                console.log('Authentication failed, redirecting to login');
                this.logout();
                return null;
            }

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('API request failed:', error);
            this.showError('Network error. Please try again.');
            return null;
        }
    }

    setupEventListeners() {
        // Header actions
        document.getElementById('logout-btn').addEventListener('click', () => this.logout());

        // Category actions
        document.getElementById('add-category-btn').addEventListener('click', () => this.showCategoryModal());
        document.getElementById('add-command-btn').addEventListener('click', () => this.showCommandModal());

        // Search
        document.getElementById('search-input').addEventListener('input', (e) => this.handleSearch(e.target.value));

        // Modal handlers
        this.setupModalHandlers();
    }

    setupModalHandlers() {
        // Category modal
        const categoryModal = document.getElementById('category-modal');
        const categoryForm = document.getElementById('category-form');
        const categoryClose = categoryModal.querySelector('.close');
        const categoryCancelBtn = categoryModal.querySelector('.cancel-btn');

        categoryClose.addEventListener('click', () => this.hideCategoryModal());
        categoryCancelBtn.addEventListener('click', () => this.hideCategoryModal());
        categoryForm.addEventListener('submit', (e) => this.handleCategorySubmit(e));

        // Command modal
        const commandModal = document.getElementById('command-modal');
        const commandForm = document.getElementById('command-form');
        const commandClose = commandModal.querySelector('.close');
        const commandCancelBtn = commandModal.querySelector('.cancel-btn');

        commandClose.addEventListener('click', () => this.hideCommandModal());
        commandCancelBtn.addEventListener('click', () => this.hideCommandModal());
        commandForm.addEventListener('submit', (e) => this.handleCommandSubmit(e));

        // Close modals when clicking outside
        window.addEventListener('click', (e) => {
            if (e.target === categoryModal) this.hideCategoryModal();
            if (e.target === commandModal) this.hideCommandModal();
        });
    }

    updateUserInfo() {
        document.getElementById('current-user').textContent = this.currentUser;
    }

    logout() {
        localStorage.removeItem('authToken');
        localStorage.removeItem('username');
        window.location.href = '/login';
    }

    async loadDataFromServer() {
        this.showLoading(true);

        try {
            // Load categories and commands from server
            const [categoriesData, commandsData] = await Promise.all([
                this.apiRequest('/api/categories'),
                this.apiRequest('/api/commands')
            ]);

            if (categoriesData) {
                this.categories = categoriesData;
            }

            if (commandsData) {
                this.commands = commandsData;
            }

            // If no data exists, add demo data
            if (this.categories.length === 0) {
                await this.addDemoData();
            }

            this.renderCategories();
        } catch (error) {
            console.error('Failed to load data:', error);
            this.showError('Failed to load data from server');
        } finally {
            this.showLoading(false);
        }
    }

    async addDemoData() {
        const demoCategories = [
            { name: 'Linux Commands', description: 'Basic Linux terminal commands', parentId: null },
            { name: 'Network Tools', description: 'Network diagnostic tools', parentId: null },
            { name: 'Git Commands', description: 'Version control with Git', parentId: null },
            { name: 'Docker', description: 'Container management', parentId: null }
        ];

        // Create demo categories
        for (const category of demoCategories) {
            await this.apiRequest('/api/categories', {
                method: 'POST',
                body: JSON.stringify(category)
            });
        }

        // Reload data after adding demo categories
        await this.loadDataFromServer();

        // Add demo commands
        const fileOpsCategory = this.categories.find(cat => cat.name === 'Linux Commands');
        const networkCategory = this.categories.find(cat => cat.name === 'Network Tools');
        const gitCategory = this.categories.find(cat => cat.name === 'Git Commands');

        if (fileOpsCategory) {
            const demoCommands = [
                {
                    categoryId: fileOpsCategory.id,
                    name: 'ls',
                    syntax: 'ls [options] [directory]',
                    description: 'List directory contents',
                    examples: 'ls -la\nls -lh /home\nls --color=auto',
                    tags: 'linux,file,directory,list'
                },
                {
                    categoryId: fileOpsCategory.id,
                    name: 'cp',
                    syntax: 'cp [options] source destination',
                    description: 'Copy files or directories',
                    examples: 'cp file.txt backup.txt\ncp -r folder/ backup_folder/\ncp -v *.txt /backup/',
                    tags: 'linux,file,copy'
                }
            ];

            for (const command of demoCommands) {
                await this.apiRequest('/api/commands', {
                    method: 'POST',
                    body: JSON.stringify(command)
                });
            }
        }

        if (networkCategory) {
            await this.apiRequest('/api/commands', {
                method: 'POST',
                body: JSON.stringify({
                    categoryId: networkCategory.id,
                    name: 'ping',
                    syntax: 'ping [options] hostname',
                    description: 'Send ICMP echo requests to network hosts',
                    examples: 'ping google.com\nping -c 4 192.168.1.1\nping -i 2 example.com',
                    tags: 'network,diagnostic,icmp'
                })
            });
        }

        if (gitCategory) {
            await this.apiRequest('/api/commands', {
                method: 'POST',
                body: JSON.stringify({
                    categoryId: gitCategory.id,
                    name: 'git clone',
                    syntax: 'git clone [options] <repository> [directory]',
                    description: 'Clone a repository into a new directory',
                    examples: 'git clone https://github.com/user/repo.git\ngit clone --depth 1 repo.git\ngit clone -b branch repo.git',
                    tags: 'git,clone,repository'
                })
            });
        }

        // Reload data after adding demo commands
        await this.loadDataFromServer();
    }

    renderCategories() {
        const container = document.getElementById('categories-tree');
        container.innerHTML = '';

        const rootCategories = this.categories.filter(cat => !cat.parentId);
        rootCategories.forEach(category => {
            container.appendChild(this.createCategoryElement(category));
        });
    }

    createCategoryElement(category) {
        const div = document.createElement('div');
        div.className = 'category-item';

        const subcategories = this.categories.filter(cat => cat.parentId === category.id);
        const hasSubcategories = subcategories.length > 0;

        div.innerHTML = `
            <div class="category-header" data-category-id="${category.id}">
                <span class="category-toggle">${hasSubcategories ? '▼' : '•'}</span>
                <span class="category-name">${category.name}</span>
                <div class="category-actions">
                    <button class="category-action-btn add-sub-btn" title="Add Subcategory">+</button>
                    <button class="category-action-btn edit-btn" title="Edit">✎</button>
                    <button class="category-action-btn delete-btn" title="Delete">×</button>
                </div>
            </div>
            ${hasSubcategories ? '<div class="subcategories"></div>' : ''}
        `;

        const header = div.querySelector('.category-header');
        const subcategoriesContainer = div.querySelector('.subcategories');

        // Category selection
        header.addEventListener('click', (e) => {
            if (!e.target.classList.contains('category-action-btn')) {
                this.selectCategory(category.id);
            }
        });

        // Category actions
        div.querySelector('.add-sub-btn').addEventListener('click', (e) => {
            e.stopPropagation();
            this.showCategoryModal(category.id);
        });

        div.querySelector('.edit-btn').addEventListener('click', (e) => {
            e.stopPropagation();
            this.editCategory(category);
        });

        div.querySelector('.delete-btn').addEventListener('click', (e) => {
            e.stopPropagation();
            this.deleteCategory(category.id);
        });

        // Render subcategories
        if (hasSubcategories && subcategoriesContainer) {
            subcategories.forEach(subcat => {
                subcategoriesContainer.appendChild(this.createCategoryElement(subcat));
            });
        }

        return div;
    }

    selectCategory(categoryId) {
        // Update UI
        document.querySelectorAll('.category-header').forEach(header => {
            header.classList.remove('active');
        });

        const selectedHeader = document.querySelector(`[data-category-id="${categoryId}"]`);
        if (selectedHeader) {
            selectedHeader.classList.add('active');
        }

        this.currentCategoryId = categoryId;
        const category = this.categories.find(cat => cat.id === categoryId);

        document.getElementById('current-category').textContent = category ? category.name : 'Unknown Category';
        document.getElementById('add-command-btn').style.display = 'block';

        this.renderCommands();
    }

    renderCommands() {
        const container = document.getElementById('commands-list');
        const categoryCommands = this.commands.filter(cmd => cmd.categoryId === this.currentCategoryId);

        if (categoryCommands.length === 0) {
            container.innerHTML = `
                <div class="welcome-message">
                    <h3>No commands yet</h3>
                    <p>Click "Add Command" to create your first command in this category.</p>
                </div>
            `;
            return;
        }

        container.innerHTML = '';
        categoryCommands.forEach(command => {
            container.appendChild(this.createCommandElement(command));
        });
    }

    createCommandElement(command) {
        const div = document.createElement('div');
        div.className = 'command-card';

        const tags = command.tags ? command.tags.split(',').map(tag => 
            `<span class="tag">${tag.trim()}</span>`
        ).join('') : '';

        div.innerHTML = `
            <div class="command-header">
                <h3 class="command-name">${command.name}</h3>
                <div class="command-actions">
                    <button class="edit-btn" title="Edit">✎</button>
                    <button class="delete-btn" title="Delete">×</button>
                </div>
            </div>
            ${command.syntax ? `<div class="command-syntax">${command.syntax}</div>` : ''}
            ${command.description ? `<div class="command-description">${command.description}</div>` : ''}
            ${command.examples ? `<div class="command-examples">${command.examples}</div>` : ''}
            ${tags ? `<div class="command-tags">${tags}</div>` : ''}
        `;

        // Command actions
        div.querySelector('.edit-btn').addEventListener('click', () => this.editCommand(command));
        div.querySelector('.delete-btn').addEventListener('click', () => this.deleteCommand(command.id));

        return div;
    }

    // Category modal methods
    showCategoryModal(parentId = null) {
        document.getElementById('category-id').value = '';
        document.getElementById('parent-category-id').value = parentId || '';
        document.getElementById('category-name').value = '';
        document.getElementById('category-description').value = '';
        document.getElementById('category-modal-title').textContent = parentId ? 'Add Subcategory' : 'Add Category';
        document.getElementById('category-modal').style.display = 'block';
    }

    hideCategoryModal() {
        document.getElementById('category-modal').style.display = 'none';
    }

    editCategory(category) {
        document.getElementById('category-id').value = category.id;
        document.getElementById('parent-category-id').value = category.parentId || '';
        document.getElementById('category-name').value = category.name;
        document.getElementById('category-description').value = category.description || '';
        document.getElementById('category-modal-title').textContent = 'Edit Category';
        document.getElementById('category-modal').style.display = 'block';
    }

    async handleCategorySubmit(e) {
        e.preventDefault();

        const id = document.getElementById('category-id').value;
        const parentId = document.getElementById('parent-category-id').value || null;
        const name = document.getElementById('category-name').value;
        const description = document.getElementById('category-description').value;

        const categoryData = { name, description, parentId };

        let success = false;

        if (id) {
            // Edit existing category
            const result = await this.apiRequest(`/api/categories/${id}`, {
                method: 'PUT',
                body: JSON.stringify(categoryData)
            });
            success = result !== null;
        } else {
            // Add new category
            const result = await this.apiRequest('/api/categories', {
                method: 'POST',
                body: JSON.stringify(categoryData)
            });
            success = result !== null;
        }

        if (success) {
            await this.loadDataFromServer();
            this.hideCategoryModal();
            this.showSuccess('Category saved successfully!');
        }
    }

    async deleteCategory(categoryId) {
        if (confirm('Are you sure you want to delete this category and all its commands?')) {
            const result = await this.apiRequest(`/api/categories/${categoryId}`, {
                method: 'DELETE'
            });

            if (result) {
                await this.loadDataFromServer();

                // Clear main content if current category was deleted
                if (this.currentCategoryId === categoryId) {
                    this.currentCategoryId = null;
                    document.getElementById('current-category').textContent = 'Select a category';
                    document.getElementById('add-command-btn').style.display = 'none';
                    document.getElementById('commands-list').innerHTML = `
                        <div class="welcome-message">
                            <h3>Welcome to Command Notes</h3>
                            <p>Select a category from the sidebar to view commands, or create a new category to get started.</p>
                        </div>
                    `;
                }

                this.showSuccess('Category deleted successfully!');
            }
        }
    }

    // Command modal methods
    showCommandModal() {
        if (!this.currentCategoryId) {
            alert('Please select a category first');
            return;
        }

        document.getElementById('command-id').value = '';
        document.getElementById('command-category-id').value = this.currentCategoryId;
        document.getElementById('command-name').value = '';
        document.getElementById('command-syntax').value = '';
        document.getElementById('command-description').value = '';
        document.getElementById('command-examples').value = '';
        document.getElementById('command-tags').value = '';
        document.getElementById('command-modal-title').textContent = 'Add Command';
        document.getElementById('command-modal').style.display = 'block';
    }

    hideCommandModal() {
        document.getElementById('command-modal').style.display = 'none';
    }

    editCommand(command) {
        document.getElementById('command-id').value = command.id;
        document.getElementById('command-category-id').value = command.categoryId;
        document.getElementById('command-name').value = command.name;
        document.getElementById('command-syntax').value = command.syntax || '';
        document.getElementById('command-description').value = command.description || '';
        document.getElementById('command-examples').value = command.examples || '';
        document.getElementById('command-tags').value = command.tags || '';
        document.getElementById('command-modal-title').textContent = 'Edit Command';
        document.getElementById('command-modal').style.display = 'block';
    }

    async handleCommandSubmit(e) {
        e.preventDefault();

        const id = document.getElementById('command-id').value;
        const categoryId = document.getElementById('command-category-id').value;
        const name = document.getElementById('command-name').value;
        const syntax = document.getElementById('command-syntax').value;
        const description = document.getElementById('command-description').value;
        const examples = document.getElementById('command-examples').value;
        const tags = document.getElementById('command-tags').value;

        const commandData = { categoryId, name, syntax, description, examples, tags };

        let success = false;

        if (id) {
            // Edit existing command
            const result = await this.apiRequest(`/api/commands/${id}`, {
                method: 'PUT',
                body: JSON.stringify(commandData)
            });
            success = result !== null;
        } else {
            // Add new command
            const result = await this.apiRequest('/api/commands', {
                method: 'POST',
                body: JSON.stringify(commandData)
            });
            success = result !== null;
        }

        if (success) {
            await this.loadDataFromServer();
            this.renderCommands();
            this.hideCommandModal();
            this.showSuccess('Command saved successfully!');
        }
    }

    async deleteCommand(commandId) {
        if (confirm('Are you sure you want to delete this command?')) {
            const result = await this.apiRequest(`/api/commands/${commandId}`, {
                method: 'DELETE'
            });

            if (result) {
                await this.loadDataFromServer();
                this.renderCommands();
                this.showSuccess('Command deleted successfully!');
            }
        }
    }

    handleSearch(query) {
        if (!query.trim()) {
            this.renderCategories();
            return;
        }

        const filteredCategories = this.categories.filter(cat =>
            cat.name.toLowerCase().includes(query.toLowerCase()) ||
            (cat.description && cat.description.toLowerCase().includes(query.toLowerCase()))
        );

        const filteredCommands = this.commands.filter(cmd =>
            cmd.name.toLowerCase().includes(query.toLowerCase()) ||
            (cmd.description && cmd.description.toLowerCase().includes(query.toLowerCase())) ||
            (cmd.tags && cmd.tags.toLowerCase().includes(query.toLowerCase()))
        );

        // Render filtered results
        const container = document.getElementById('categories-tree');
        container.innerHTML = '';

        if (filteredCategories.length === 0 && filteredCommands.length === 0) {
            container.innerHTML = '<div style="padding: 20px; text-align: center; color: #7f8c8d;">No results found</div>';
            return;
        }

        // Show matching categories
        filteredCategories.forEach(category => {
            container.appendChild(this.createCategoryElement(category));
        });

        // Show matching commands
        if (filteredCommands.length > 0) {
            const commandsSection = document.createElement('div');
            commandsSection.innerHTML = '<div style="padding: 10px; font-weight: bold; color: #2c3e50;">Matching Commands:</div>';

            filteredCommands.forEach(command => {
                const commandDiv = document.createElement('div');
                commandDiv.className = 'category-header';
                commandDiv.style.marginLeft = '10px';
                commandDiv.innerHTML = `<span class="category-name">${command.name}</span>`;
                commandDiv.addEventListener('click', () => {
                    this.selectCategory(command.categoryId);
                });
                commandsSection.appendChild(commandDiv);
            });

            container.appendChild(commandsSection);
        }
    }

    // Utility methods
    showLoading(show) {
        // You can implement a loading spinner here
        if (show) {
            console.log('Loading...');
        } else {
            console.log('Loading complete');
        }
    }

    showError(message) {
        // Simple error display - you can enhance this
        alert('Error: ' + message);
    }

    showSuccess(message) {
        // Simple success display - you can enhance this
        console.log('Success: ' + message);

        // Optional: Show a temporary success message
        const successDiv = document.createElement('div');
        successDiv.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #27ae60;
            color: white;
            padding: 15px 20px;
            border-radius: 5px;
            z-index: 1000;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        `;
        successDiv.textContent = message;
        document.body.appendChild(successDiv);

        setTimeout(() => {
            document.body.removeChild(successDiv);
        }, 3000);
    }
}

// Initialize notes manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new NotesManager();
});
