// static/edit.js
(function() {
    // 配置 Monaco Editor
    window.MonacoEnvironment = {
        getWorkerUrl: function (moduleId, label) {
            if (label === 'markdown') {
                return './monaco-markdown.worker.js';
            }
            return './monaco-editor.worker.js';
        }
    };

    // 加载 Monaco Editor
    require.config({
        paths: {
            'vs': 'https://cdn.jsdelivr.net/npm/monaco-editor@0.52.2/min/vs'
        }
    });

    require(['vs/editor/editor.main'], function() {
        const editor = monaco.editor.create(document.getElementById('editor-container'), {
            value: document.getElementById('hidden-content').value,
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
        updatePreview(editor.getValue());
    });

    // 实时预览更新函数
    function updatePreview(content) {
        try {
            const previewContainer = document.getElementById('preview-container');
            
            // 1. 消毒内容
            const cleanContent = DOMPurify.sanitize(content);
            
            // 2. 转换 Markdown
            const htmlContent = marked.parse(cleanContent);
            
            // 3. 更新预览内容
            previewContainer.innerHTML = htmlContent;
            
            // 4. 渲染数学公式
            renderMathInElement(previewContainer, {
                delimiters: [
                    { left: '$$', right: '$$', display: true },  // 行间公式
                    { left: '$', right: '$', display: false }   // 行内公式
                ],
                throwOnError: false
            });
            
            // 5. 高亮代码块
            document.querySelectorAll('pre code').forEach((block) => {
                hljs.highlightElement(block);
            });
        } catch (error) {
            console.error('预览更新失败:', error);
        }
    }
})();