// Toggle between login & registration form
function toggleForm() {
    document.getElementById("loginContainer").classList.toggle("d-none");
    document.getElementById("registerContainer").classList.toggle("d-none");
}

// Registration
document.getElementById("registerForm").addEventListener("submit", function(event) {
    event.preventDefault();

    let name = document.getElementById("registerName").value;
    let email = document.getElementById("registerEmail").value;
    let password = document.getElementById("registerPassword").value;

    let users = JSON.parse(localStorage.getItem("reviewers")) || {};

    if (users[email]) {
        alert("Email already registered! Please login.");
        return;
    }

    users[email] = { name, password, assignedPapers: 0, pendingReviews: 0, completedReviews: 0 };
    localStorage.setItem("reviewers", JSON.stringify(users));

    alert("Registration successful! Please login.");
    toggleForm();
});

// Login
document.getElementById("loginForm").addEventListener("submit", function(event) {
    event.preventDefault();

    let email = document.getElementById("loginEmail").value;
    let password = document.getElementById("loginPassword").value;

    let users = JSON.parse(localStorage.getItem("reviewers")) || {};

    if (!users[email] || users[email].password !== password) {
        alert("Invalid email or password!");
        return;
    }

    sessionStorage.setItem("loggedInReviewer", email);
    window.location.href = "dashboard.html";
});

// Load Dashboard Data
if (window.location.pathname.includes("dashboard.html")) {
    let email = sessionStorage.getItem("loggedInReviewer");
    let users = JSON.parse(localStorage.getItem("reviewers")) || {};

    if (!email || !users[email]) {
        alert("Unauthorized Access! Redirecting to Login...");
        window.location.href = "index.html";
    } else {
        let user = users[email];
        document.getElementById("reviewerName").innerText = user.name;
        document.getElementById("reviewerEmail").innerText = email;
        document.getElementById("assignedPapers").innerText = user.assignedPapers;
        document.getElementById("pendingReviews").innerText = user.pendingReviews;
        document.getElementById("completedReviews").innerText = user.completedReviews;
    }
}

// Logout
function logout() {
    sessionStorage.removeItem("loggedInReviewer");
    window.location.href = "index.html";
}
