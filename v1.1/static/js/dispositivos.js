var dispositivos = [];
var currentPage = 1;
var rowsPerPage = 10;

function carregarDispositivos() {
    fetch('/api/dispositivos')
        .then(response => response.json())
        .then(data => {
            dispositivos = data;
            mostrarDispositivos();
        })
        .catch(error => console.error('Erro ao carregar os alertas:', error));
}

function mostrarDispositivos() {
    var corpoTabela = document.getElementById("corpoTabela");
    var filtroOpcao = document.getElementById("filtroOpcao").value;
    var input = document.getElementById("myInput").value.toUpperCase();
    corpoTabela.innerHTML = "";

    var totalDispositivos = 0;
    var filteredDispositivos = dispositivos.filter(function(dispositivo) {
        var incluirDispositivo = false;

        // Verifique qual filtro foi selecionado (mensagem ou escola)
       
        if (filtroOpcao === "1") {  // Filtro por mensagem
            if (dispositivo.mac_dispositivo.toUpperCase().indexOf(input) > -1) {
                incluirDispositivo = true;
            }
        }
        else if (filtroOpcao === "2") {
            if (dispositivo.solicitante.toUpperCase().indexOf(input) > -1) { 
                incluirDispositivo = true;
            }
        }
        else if (filtroOpcao === "3") {
            if (dispositivo.escola.toUpperCase().indexOf(input) > -1) { 
                incluirDispositivo = true;
            }
        }

        if (incluirDispositivo) totalDispositivos++;
        return incluirDispositivo;
    });

    atualizarPaginacao(filteredDispositivos.length);

    var startIndex = (currentPage - 1) * rowsPerPage;
    var endIndex = startIndex + rowsPerPage;
    for (var i = startIndex; i < endIndex && i < filteredDispositivos.length; i++) {
        var dispositivo = filteredDispositivos[i];
        var row = document.createElement("tr");

        row.innerHTML = "<td><input type='checkbox'></td>" +
            "<td>" + (dispositivo.mac_dispositivo || 'Não identificado') + "</td>" +
            "<td>" + (dispositivo.solicitante || 'Não identificado') + "</td>" +
            "<td>" + (dispositivo.escola || 'Não especificada') + "</td>" +
            "<td>" + ('Android') + "</td>" +
            "<td>" + (dispositivo.message || 'Ativo')+ "</td>" +
            "<td><span class='material-symbols-outlined btn_editar' data-alerta-id='" + dispositivo.id + "'>edit</span></td>";

        corpoTabela.appendChild(row);
    }

    document.getElementById("quantidadeDispositivos").innerText = "Quantidade de Dispositivos: " + totalDispositivos;

    editarAlerta();
}

// Função para formatar a data
function formatarData(data) {
    var date = new Date(data);
    var options = { year: 'numeric', month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' };
    return date.toLocaleDateString('pt-BR', options);
}

function editarAlerta() {
    document.querySelectorAll('.btn_editar').forEach(function(btn) {
        btn.addEventListener('click', function(event) {
            event.preventDefault();  // Prevent default button behavior

            //const alertaId = btn.getAttribute('data-alerta-id');  // Alterar para 'data-alerta-id'
            const usuarioId = btn.getAttribute('data-usuario-id');

            // Redirect to the edit page with the alerta ID
            window.location.href = `/user/usuarios/usuario/${usuarioId}`;
            //window.location.href = `/alertas/editar/${alertaId}`;  // Corrigir o caminho, se necessário
        });
    });
}

// Função para limpar o campo de pesquisa ao trocar o filtro
document.getElementById('filtroOpcao').addEventListener('change', function() {
    var inputPesquisa = document.getElementById('myInput');
    
    // Limpar o campo de pesquisa ao trocar o filtro
    inputPesquisa.value = '';

    // Atualizar o placeholder conforme o filtro selecionado
    if (this.value == "1") {
        inputPesquisa.placeholder = "Pesquisar por MAC...";
    } 
    else if (this.value == "2") {
        inputPesquisa.placeholder = "Pesquisar por Usuário...";
    }
    else if (this.value == "3") {
        inputPesquisa.placeholder = "Pesquisar por Escola...";
    }  
    
    // Atualizar a tabela após mudar o filtro
    //filtrarTabela();
});

function atualizarPaginacao(totalRows) {
    var paginacao = document.getElementById("paginacao");
    var totalPages = Math.ceil(totalRows / rowsPerPage);
    paginacao.innerHTML = "";
    for (var i = 1; i <= totalPages; i++) {
        var link = document.createElement("a");
        link.href = "#";
        link.innerText = i;
        if (i === currentPage) {
            link.className = "active";
        }
        link.onclick = function() {
            currentPage = parseInt(this.innerText);
            mostrarDispositivos();
        };
        paginacao.appendChild(link);
    }
}

function filtrarTabela() {
    currentPage = 1;
    mostrarDispositivos();
}

carregarDispositivos();
