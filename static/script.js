function openTab(tabName) {
    // Hide all tab content
    const contents = document.getElementsByClassName('tab-content');
    for (let i = 0; i < contents.length; i++) {
        contents[i].classList.remove('active');
    }

    // Deactivate all buttons
    const buttons = document.getElementsByClassName('tab-btn');
    for (let i = 0; i < buttons.length; i++) {
        buttons[i].classList.remove('active');
    }

    // Show current tab and activate button
    document.getElementById(tabName).classList.add('active');

    // Find the button that calls this function with the same argument?
    // Actually we can just find it by index or logic.
    // Simpler: iterate buttons and if onclick contains tabName...
    // Or just let CSS handle it via checking 'active' class on button passed manually?
    // Let's re-query based on text content or an ID.
    // For simplicity, I'll rely on the classlist management above.

    // Highlight the clicked button
    const activeBtn = Array.from(buttons).find(btn => btn.onclick.toString().includes(tabName));
    if (activeBtn) activeBtn.classList.add('active');
}

// File Upload Feedback
document.querySelectorAll('input[type="file"]').forEach(input => {
    input.addEventListener('change', function (e) {
        const fileName = e.target.files[0] ? e.target.files[0].name : "Choose Image...";
        const label = e.target.nextElementSibling;
        label.innerHTML = `<i class="fas fa-check"></i> ${fileName}`;
        label.style.borderColor = "var(--success)";
        label.style.color = "var(--success)";
    });
});
