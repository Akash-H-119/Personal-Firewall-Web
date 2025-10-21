const socket = io();

socket.on('new_packet', (data) => {
    const tbody = document.querySelector("#packets-table tbody");
    const tr = document.createElement("tr");

    tr.innerHTML = `
        <td>${data.info.src || '-'}</td>
        <td>${data.info.dst || '-'}</td>
        <td>${data.info.sport || '-'}</td>
        <td>${data.info.dport || '-'}</td>
        <td>${data.info.protocol || '-'}</td>
        <td>${data.blocked ? 'YES' : 'NO'}</td>
    `;

    tbody.prepend(tr);
});
