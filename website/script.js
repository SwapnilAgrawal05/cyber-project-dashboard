function fetchThreats() {
    document.getElementById("threat-data").innerHTML = "<p>Loading threat data...</p>";

    setTimeout(() => {
        document.getElementById("threat-data").innerHTML = "<p>🚨 No new threats detected.</p>";
    }, 2000);
}
