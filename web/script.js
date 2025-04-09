// script.js

window.addEventListener("DOMContentLoaded", () => {
    const historyTable = document.getElementById("history-table");
    if (!historyTable) return;

    fetch("/api/passwords")
        .then(res => res.json())
        .then(data => {
            if (data.length === 0) {
                historyTable.innerHTML = '<tr><td colspan="4">No history available.</td></tr>';
                return;
            }

            data.forEach((item, index) => {
                const row = document.createElement("tr");
                row.innerHTML = `
                    <td>${index + 1}</td>
                    <td>${item.password}</td>
                    <td>${item.created_at}</td>
                    <td>${item.ip}</td>
                `;
                historyTable.appendChild(row);
            });
        })
        .catch(err => {
            historyTable.innerHTML = '<tr><td colspan="4">Failed to load data</td></tr>';
            console.error(err);
        });
});
