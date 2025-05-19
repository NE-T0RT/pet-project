document.addEventListener('DOMContentLoaded', () => {
    const themeToggleButton = document.getElementById('theme-toggle');
    const themeIcon = document.getElementById('theme-icon');

    const currentTheme = localStorage.getItem('theme');
    if (currentTheme === 'dark') {
        document.body.classList.add('dark-theme');
        themeIcon.src = themeIcon.src.replace('sun.png', 'moon.png');
    }

    themeToggleButton.addEventListener('click', () => {
        if (document.body.classList.contains('dark-theme')) {
            // Переключение на светлую тему
            document.body.classList.remove('dark-theme');
            themeIcon.src = themeIcon.src.replace('moon.png', 'sun.png');
            localStorage.setItem('theme', 'light');
        } else {
            // Переключение на темную тему
            document.body.classList.add('dark-theme');
            themeIcon.src = themeIcon.src.replace('sun.png', 'moon.png');
            localStorage.setItem('theme', 'dark');
        }
    });
});
