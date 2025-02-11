// static/view.js
(function() {
    // 初始化 Markdown 渲染
    function renderMarkdown() {
        try {
            const markdownContainer = document.getElementById('markdown-content');
            const content = markdownContainer.textContent;

            // 1. 消毒内容
            // const cleanContent = DOMPurify.sanitize(content);
            const cleanContent = content;

            // 2. 转换 Markdown
            const htmlContent = marked.parse(cleanContent, {
                breaks: true,
                highlight: function(code, lang) {
                    const validLang = hljs.getLanguage(lang) ? lang : 'plaintext';
                    return hljs.highlight(code, { language: validLang }).value;
                }
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

            // 5. 高亮代码块
            document.querySelectorAll('pre code').forEach((block) => {
                hljs.highlightElement(block);
            });
        } catch (error) {
            console.error('渲染失败:', error);
        }
    }

    // 页面加载完成后执行渲染
    document.addEventListener('DOMContentLoaded', renderMarkdown);
})();