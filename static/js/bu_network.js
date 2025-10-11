class NetworkAnimation {
    constructor() {
        this.svg = document.getElementById('bu_network-svg');
        this.width = window.innerWidth;
        this.height = window.innerHeight;
        this.nodes = [];
        this.connections = [];
        this.mouse = { x: null, y: null };
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

        window.addEventListener('mousemove', (e) => {
            this.mouse.x = e.clientX;
            this.mouse.y = e.clientY;
        });

        window.addEventListener('mouseleave', () => {
            this.mouse.x = null;
            this.mouse.y = null;
        });
    }

    createNodes() {
        const nodeCount = 120; // Increased for density
        this.nodes = [];
        for (let i = 0; i < nodeCount; i++) {
            this.nodes.push({
                x: Math.random() * this.width,
                y: Math.random() * this.height,
                vx: (Math.random() - 0.5) * 0.4,
                vy: (Math.random() - 0.5) * 0.4,
                radius: Math.random() * 2 + 1
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
        const maxDistance = 180; // Increased for density
        this.connections = [];
        for (let i = 0; i < this.nodes.length; i++) {
            for (let j = i + 1; j < this.nodes.length; j++) {
                const distance = this.getDistance(this.nodes[i], this.nodes[j]);
                if (distance < maxDistance) {
                    this.connections.push({
                        node1: this.nodes[i],
                        node2: this.nodes[j],
                        opacity: Math.max(0.05, 1 - (distance / maxDistance))
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
            // NO Mouse attraction
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

            // Slow down velocity slightly for stability
            node.vx *= 0.98;
            node.vy *= 0.98;
        });
    }

    render() {
        this.svg.innerHTML = '';
        this.svg.setAttribute('viewBox', `0 0 ${this.width} ${this.height}`);

        this.createConnections();

        // Render connections (lines)
        this.connections.forEach(conn => {
            const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
            line.setAttribute('x1', conn.node1.x);
            line.setAttribute('y1', conn.node1.y);
            line.setAttribute('x2', conn.node2.x);
            line.setAttribute('y2', conn.node2.y);
            line.setAttribute('stroke', '#222');
            line.setAttribute('stroke-width', '1');
            line.setAttribute('stroke-opacity', conn.opacity * 0.4);
            this.svg.appendChild(line);
        });

        // Draw lines from mouse to nearby nodes
        if (this.mouse.x !== null && this.mouse.y !== null) {
            this.nodes.forEach(node => {
                const dist = this.getDistance(node, this.mouse);
                if (dist < 140) {
                    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                    line.setAttribute('x1', node.x);
                    line.setAttribute('y1', node.y);
                    line.setAttribute('x2', this.mouse.x);
                    line.setAttribute('y2', this.mouse.y);
                    line.setAttribute('stroke', '#222');
                    line.setAttribute('stroke-width', '1');
                    line.setAttribute('stroke-opacity', (1 - dist / 140) * 0.5);
                    this.svg.appendChild(line);
                }
            });

            // Draw a subtle circle at the mouse position
            const mouseCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
            mouseCircle.setAttribute('cx', this.mouse.x);
            mouseCircle.setAttribute('cy', this.mouse.y);
            mouseCircle.setAttribute('r', 4);
            mouseCircle.setAttribute('fill', '#222');
            mouseCircle.setAttribute('fill-opacity', '0.3');
            this.svg.appendChild(mouseCircle);
        }

        // Render nodes (dots)
        this.nodes.forEach(node => {
            const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
            circle.setAttribute('cx', node.x);
            circle.setAttribute('cy', node.y);
            circle.setAttribute('r', node.radius);
            circle.setAttribute('fill', '#222');
            circle.setAttribute('fill-opacity', '0.7');
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

document.addEventListener('DOMContentLoaded', () => {
    new NetworkAnimation();
});
