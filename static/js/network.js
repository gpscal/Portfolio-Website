class NetworkAnimation {
    constructor() {
        this.svg = document.getElementById('network-svg');
        this.width = window.innerWidth;
        this.height = window.innerHeight;
        this.nodes = [];
        this.connections = [];
        this.animationId = null;
        this.init();
    }

    init() {
        this.createNodes();
        this.render();
        this.animate();
        
        window.addEventListener('resize', () => {
            this.width = window.innerWidth;
            this.height = window.innerHeight;
            this.svg.setAttribute('viewBox', `0 0 ${this.width} ${this.height}`);
            this.updateNodeBounds();
        });
    }

    createNodes() {
        const nodeCount = 50;
        this.nodes = [];
        
        for (let i = 0; i < nodeCount; i++) {
            this.nodes.push({
                x: Math.random() * this.width,
                y: Math.random() * this.height,
                vx: (Math.random() - 0.5) * 0.5,
                vy: (Math.random() - 0.5) * 0.5,
                radius: Math.random() * 3 + 1
            });
        }
    }

    updateNodeBounds() {
        this.nodes.forEach(node => {
            if (node.x > this.width) node.x = this.width;
            if (node.y > this.height) node.y = this.height;
        });
    }

    createConnections() {
        const maxDistance = 150;
        this.connections = [];
        
        for (let i = 0; i < this.nodes.length; i++) {
            for (let j = i + 1; j < this.nodes.length; j++) {
                const distance = this.getDistance(this.nodes[i], this.nodes[j]);
                if (distance < maxDistance) {
                    this.connections.push({
                        node1: this.nodes[i],
                        node2: this.nodes[j],
                        opacity: Math.max(0.1, 1 - (distance / maxDistance))
                    });
                }
            }
        }
    }

    getDistance(node1, node2) {
        const dx = node1.x - node2.x;
        const dy = node1.y - node2.y;
        return Math.sqrt(dx * dx + dy * dy);
    }

    updateNodes() {
        this.nodes.forEach(node => {
            // Update position
            node.x += node.vx;
            node.y += node.vy;

            // Bounce off walls
            if (node.x <= 0 || node.x >= this.width) {
                node.vx *= -1;
                node.x = Math.max(0, Math.min(this.width, node.x));
            }
            if (node.y <= 0 || node.y >= this.height) {
                node.vy *= -1;
                node.y = Math.max(0, Math.min(this.height, node.y));
            }
        });
    }

    render() {
        this.svg.innerHTML = '';
        this.svg.setAttribute('viewBox', `0 0 ${this.width} ${this.height}`);

        this.createConnections();

        // Render connections
        this.connections.forEach(conn => {
            const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
            line.setAttribute('x1', conn.node1.x);
            line.setAttribute('y1', conn.node1.y);
            line.setAttribute('x2', conn.node2.x);
            line.setAttribute('y2', conn.node2.y);
            line.setAttribute('stroke', '#bdc3c7');
            line.setAttribute('stroke-width', '1');
            line.setAttribute('stroke-opacity', conn.opacity * 0.6);
            this.svg.appendChild(line);
        });

        // Render nodes
        this.nodes.forEach(node => {
            const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
            circle.setAttribute('cx', node.x);
            circle.setAttribute('cy', node.y);
            circle.setAttribute('r', node.radius);
            circle.setAttribute('fill', '#34495e');
            circle.setAttribute('fill-opacity', '0.8');
            this.svg.appendChild(circle);
        });
    }

    animate() {
        this.updateNodes();
        this.render();
        this.animationId = requestAnimationFrame(() => this.animate());
    }

    destroy() {
        if (this.animationId) {
            cancelAnimationFrame(this.animationId);
        }
    }
}

// Initialize the network animation when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new NetworkAnimation();
});
