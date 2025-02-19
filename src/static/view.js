// static/view.js
(function() {
    // 初始化 Markdown 渲染
    function renderMarkdown() {
        try {
            const markdownContainer = document.getElementById('markdown-content');
            const content = markdownContainer.textContent;

            // 1. 消毒内容
            const cleanContent = content;

            // 2. 转换 Markdown
            const htmlContent = marked.parse(cleanContent, {
                breaks: true,
                highlight: function(code, lang) {
                    const validLang = hljs.getLanguage(lang) ? lang : 'plaintext';
                    return hljs.highlight(code, { language: validLang }).value;
                },
                pedantic: false, // 不严格遵循 CommonMark
                gfm: true,       // 启用 GitHub Flavored Markdown
            });

            // 3. 更新内容
            markdownContainer.innerHTML = htmlContent;

            // 4. 渲染数学公式
            if (window.renderMathInElement) {
                renderMathInElement(markdownContainer, {
                    delimiters: [
                        { left: '$$', right: '$$', display: true },  // 行间公式
                        { left: '$', right: '$', display: false }   // 行内公式
                    ],
                    throwOnError: false
                });
            } else {
                console.warn('KaTeX 的 auto-render 扩展未加载');
            }

            // 5. 高亮代码块并添加复制按钮
            document.querySelectorAll('pre code').forEach((block) => {
                hljs.highlightElement(block);

                // 创建复制按钮
                const copyButton = document.createElement('button');
                copyButton.className = 'btn btn-sm btn-outline-secondary copy-button';
                copyButton.textContent = '复制';
                copyButton.style.position = 'absolute';
                copyButton.style.top = '10px';
                copyButton.style.right = '10px';

                // 添加点击事件
                copyButton.addEventListener('click', () => {
                    // 获取代码块的原始内容（包含换行符）
                    const code = block.innerText || block.textContent;

                    // 去除多余的空行和制表符
                    const cleanedCode = code
                        .split('\n') // 按行分割
                        .map(line => line.trimEnd()) // 去除每行末尾的空白字符
                        .filter(line => line.length > 0) // 去除空行
                        .join('\n'); // 重新拼接为字符串

                    if (navigator.clipboard && window.isSecureContext) {
                        navigator.clipboard.writeText(cleanedCode).then(() => {
                            copyButton.textContent = '已复制';
                            setTimeout(() => {
                                copyButton.textContent = '复制';
                            }, 2000);
                        });
                    } else {
                        const textArea = document.createElement('textarea');
                        textArea.value = cleanedCode;
                        document.body.appendChild(textArea);
                        textArea.select();
                        document.execCommand('copy');
                        document.body.removeChild(textArea);
                        copyButton.textContent = '已复制';
                        setTimeout(() => {
                            copyButton.textContent = '复制';
                        }, 2000);
                    }
                });

                // 将按钮添加到代码块容器
                const pre = block.parentElement;
                pre.style.position = 'relative';
                pre.appendChild(copyButton);
            });

            // 6. 初始化行号
            hljs.initLineNumbersOnLoad();
        } catch (error) {
            console.error('渲染失败:', error);
        }
    }

    // 页面加载完成后执行渲染
    document.addEventListener('DOMContentLoaded', renderMarkdown);
})();