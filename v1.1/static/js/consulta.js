var alertas = [];
        var currentPage = 1;
        var rowsPerPage = 10;

        function carregarAlertas() {
            fetch('/api/alertas')
                .then(response => response.json())
                .then(data => {
                    alertas = data;
                    mostrarAlertas();
                })
                .catch(error => console.error('Erro ao carregar os alertas:', error));
        }

        function mostrarAlertas() {
            var corpoTabela = document.getElementById("corpoTabela");
            var filtroOpcao = document.getElementById("filtroOpcao").value;
            var input = document.getElementById("myInput").value.toUpperCase();
            corpoTabela.innerHTML = "";
        
            var totalAlertas = 0;
            var filteredAlertas = alertas.filter(function(alerta) {
                var incluirAlerta = false;
                
                // Verifique qual filtro foi selecionado (mensagem ou escola)
                if (filtroOpcao === "1") {
                    if (alerta.escola && alerta.escola.toUpperCase().indexOf(input) > -1) { // Verificar se 'alerta.escola' não é null ou undefined
                        incluirAlerta = true;
                    }
                } 
                else if (filtroOpcao === "2") {  // Filtro por solicitante
                    if (alerta.solicitante.toUpperCase().indexOf(input) > -1) {
                        incluirAlerta = true;
                    }
                }
                else if (filtroOpcao === "3") {  // Filtro por data
                    if (alerta.data_hora.toUpperCase().indexOf(input) > -1) {
                        incluirAlerta = true;
                    }
                }
                
                if (incluirAlerta) totalAlertas++;
                return incluirAlerta;
            });
        
            atualizarPaginacao(filteredAlertas.length);
        
            var startIndex = (currentPage - 1) * rowsPerPage;
            var endIndex = startIndex + rowsPerPage;
            for (var i = startIndex; i < endIndex && i < filteredAlertas.length; i++) {
                var alerta = filteredAlertas[i];
                var row = document.createElement("tr");
        
                var statusAlertado = alerta.is_seen ? "Sim" : "Não";  // "Sim" ou "Não" se alertado
                
                row.innerHTML = "<td><input type='checkbox'></td>" +
                    "<td>" + (alerta.escola || 'Não especificada') + "</td>" +
                    "<td>" + alerta.solicitante + "</td>" +
                    "<td>" + alerta.message + "</td>" +
                    "<td>" + formatarData(alerta.data_hora) + "</td>" +
                    "<td>" + statusAlertado + "</td>" + 
                    "<td><span class='material-symbols-outlined btn_editar' data-alerta-id='" + alerta.id + "'>edit</span></td>";
        
                corpoTabela.appendChild(row);
            }
        
            document.getElementById("quantidadeAlertas").innerText = "Quantidade de Alertas: " + totalAlertas;
        
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
                inputPesquisa.placeholder = "Pesquisar por Escola...";
            } 
            else if (this.value == "2") {
                inputPesquisa.placeholder = "Pesquisar por Solicitante...";
            }
            else if (this.value == "3") {
                inputPesquisa.placeholder = "Pesquisar por Data...";
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
                    mostrarAlertas();
                };
                paginacao.appendChild(link);
            }
        }

        function filtrarTabela() {
            currentPage = 1;
            mostrarAlertas();
        }

        carregarAlertas();
