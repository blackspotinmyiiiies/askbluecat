Deploying a Hugo Site with GitHub & Cloudflare Pages: A Modern Static Stack
15 January 2026
·682 words·4 mins
Deploying a Hugo Site with GitHub & Cloudflare Pages: A Modern Static Stack

The combination of Hugo, GitHub, and Cloudflare Pages creates a powerful, secure, and cost-effective pipeline for building modern websites. This stack is perfect for blogs, documentation, and portfolios, offering developer-friendly workflows with enterprise-grade performance and resilience.

This guide walks you through the complete process, from local setup to global deployment.
Prerequisites

Before you begin, ensure you have the following:

    A Hugo site (local development environment).
    A GitHub account.
    A Cloudflare account.
    Basic familiarity with Git and the command line.

Phase 1: Local Development with Hugo

First, you need a Hugo site. If you’re starting from scratch:

    Install Hugo: Follow the official installation guide for your operating system.
    Create a New Site: Run hugo new site my-awesome-site in your terminal.
    Add a Theme: Choose a theme from the Hugo Themes gallery. Most themes provide clear installation instructions, typically involving adding the theme as a Git submodule.
    Develop Locally: Use hugo server -D to start a local development server with live reload. Create content with hugo new posts/my-first-post.md.

Your site’s source code (markdown files, configuration, themes) is now ready to be managed with version control.
Phase 2: Version Control with GitHub

GitHub will host your site’s source code and act as the trigger for your deployment pipeline.

    Create a New Repository: On GitHub, create a new public repository (e.g., my-hugo-site).
    Initialize and Push: In your local site’s root directory, run:

    git init
    git add .
    git commit -m "Initial commit"
    git branch -M main
    git remote add origin https://github.com/yourusername/my-hugo-site.git
    git push -u origin main

    Site Structure: Ensure your repository contains all your source files but not the generated public/ folder. Add public/ to your .gitignore file.

Phase 3: Automated Deployment with Cloudflare Pages

Cloudflare Pages provides the build platform and global CDN. It will automatically build your Hugo site whenever you push to your GitHub repository.

    Log in to Cloudflare: Go to the Cloudflare dashboard and navigate to Pages.
    Create a New Project: Click “Create a project” and connect your GitHub account. Select the repository you just created.
    Configure Build Settings:
        Project name: Choose a name for your project (this will become part of your *.pages.dev URL).
        Production branch: main.
        Build command: hugo --gc --minify (or simply hugo).
        Build output directory: public.
        Environment variables: For most themes, no specific variables are needed here. You can add HUGO_VERSION if you require a specific version.
    Deploy! Click “Save and Deploy”. Cloudflare will immediately clone your repo, install dependencies (including Hugo), run the build command, and deploy the contents of the public folder to its global network.

Phase 4: Workflow and Custom Domain (Optional)
The Development Workflow

Your automated pipeline is now complete:

    Make changes to your site locally.
    Commit and push to the main branch on GitHub.
    Cloudflare Pages automatically detects the push, rebuilds the site, and deploys the new version. Each deployment gets a unique preview URL, and production updates are near-instantaneous.

Adding a Custom Domain

To use your own domain (e.g., askbluecat.com):

    In your Cloudflare Pages project, go to Custom domains.
    Click “Add a custom domain” and follow the prompts.
    Cloudflare will guide you to update your domain’s DNS records. Since Cloudflare also provides DNS management, this process is typically seamless if your domain is already on Cloudflare.

Why This Stack is Powerful

    Performance: Cloudflare’s global CDN ensures your static site is delivered with incredibly low latency worldwide.
    Security: Static sites have a minimal attack surface. Cloudflare provides additional layers of protection like DDoS mitigation.
    Developer Experience: GitHub manages code review and history. Cloudflare handles builds and hosting with a simple, unified interface.
    Cost: The entire stack can be free for personal use, with generous limits on both GitHub and Cloudflare Pages.

This pipeline abstracts away server management and lets you focus entirely on creating content. It’s a robust setup that scales effortlessly from a personal blog to a large documentation site.

Ready to build? Start with the Hugo Quick Start and see your site live on the global network in minutes.
