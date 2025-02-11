// static/edit.js
(function() {
    // 配置 Monaco Editor
    // window.MonacoEnvironment = {
    //     getWorkerUrl: function (moduleId, label) {
    //         if (label === 'markdown') {
    //             return './monaco-markdown.worker.js';
    //         }
    //         return './monaco-editor.worker.js';
    //     }
    // };

    // 加载 Monaco Editor
    require.config({
        paths: {
            'vs': 'https://cdn.jsdelivr.net/npm/monaco-editor@0.52.2/min/vs'
        }
    });

    require(['vs/editor/editor.main'], function() {
        // 获取隐藏的 textarea 中的内容
        const initialContent = document.getElementById('hidden-content').value;

        // 初始化 Monaco Editor
        const editor = monaco.editor.create(document.getElementById('editor-container'), {
            value: initialContent, // 使用已有的内容初始化编辑器
            language: 'markdown',
            theme: 'vs-dark',
            minimap: { enabled: false },
            automaticLayout: true
        });

        // 同步内容到隐藏字段
        editor.getModel().onDidChangeContent(() => {
            const content = editor.getValue();
            document.getElementById('hidden-content').value = content;
            updatePreview(content);
        });

        // 初始预览
        updatePreview(initialContent);
    });

    // 实时预览更新函数
    function updatePreview(content) {
        try {
            const previewContainer = document.getElementById('preview-container');
            
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
            
            // 3. 更新预览内容
            previewContainer.innerHTML = htmlContent;
            
            // 4. 渲染数学公式（确保只渲染一次）
            if (window.renderMathInElement) {
                renderMathInElement(previewContainer, {
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
            console.error('预览更新失败:', error);
        }
    }
})();