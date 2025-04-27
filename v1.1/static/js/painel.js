// Função para carregar os últimos alertas
function carregarUltimosAlertas() {
    fetch('/api/ultimos_alertas') // Substitua com o endpoint do seu backend
        .then(response => response.json()) // Supondo que o backend retorne um JSON com os alertas
        .then(alertas => {
            const ulElement = document.getElementById('ultimosAlertasList');
            ulElement.innerHTML = ''; // Limpar a lista atual para evitar duplicação

            // Adicionar os novos alertas
            alertas.forEach(alerta => {
                // Criar um item de lista com o conteúdo do alerta
                const li = document.createElement('li');
                li.classList.add('alert-item');  // Adiciona a classe de estilo
                li.style.margin = '5px';
                li.style.border = '1px solid rgb(255, 255, 255)';
                li.style.background = 'var(--red)';
                li.style.borderRadius = '5px';
                li.style.padding = '5px';


                li.innerHTML = `
                    <span class="text">
                        <h4>${alerta.titulo} Alerta Crítico em ${alerta.data_hora}</h4>
                        <p>${alerta.descricao}</p>
                        <p>Por: ${alerta.solicitante} - ${alerta.escola}</p>
                    </span>
                `;

                // Adicionar o novo item à lista
                ulElement.appendChild(li);
            });
        })
        .catch(error => {
            console.error('Erro ao carregar os alertas:', error);
        });
}

// Função para carregar as escolas que mais solicitaram alertas
function carregarEscolasMaisSolicitantes() {
    fetch('/api/escolas_mais_solicitantes') // Substitua com o endpoint correto
        .then(response => response.json())  // Supondo que o backend retorne um JSON com as escolas e quantidades de alertas
        .then(escolas => {
            const ulElement = document.getElementById('escolasMaisSolicitantesList');
            ulElement.innerHTML = ''; // Limpar a lista atual para evitar duplicação

            // Filtrar para mostrar apenas escolas com mais de 1 alerta
            escolas.filter(escola => escola.quantidade_alertas > 1)
                .forEach(escola => {
                    const li = document.createElement('li');
                    li.style.margin = '5px';
                    li.style.border = '1px solid rgb(255, 255, 255)';
                    li.style.background = 'var(--yellow)';
                    li.style.borderRadius = '5px';
                    li.style.padding = '5px';

                    li.innerHTML = `
                        <span class="text">
                            <h3>${escola.nome}</h3>
                            <p>${escola.quantidade_alertas} alertas</p>
                        </span>
                    `;

                    ulElement.appendChild(li);
                });
        })
        .catch(error => {
            console.error('Erro ao carregar as escolas mais solicitantes:', error);
        });
}

// Atualizar a lista a cada 5 segundos (5000 ms)
setInterval(carregarUltimosAlertas, 5000);

// Atualizar a lista de escolas mais solicitantes a cada 5 segundos (5000 ms)
setInterval(carregarEscolasMaisSolicitantes, 5000);

// Carregar os alertas e escolas na primeira vez quando a página for carregada
document.addEventListener('DOMContentLoaded', () => {
    carregarUltimosAlertas();
    carregarEscolasMaisSolicitantes();
});

// Atualizar a lista a cada 5 segundos (5000 ms)
//setInterval(carregarUltimosAlertas, 5000);

// Carregar os alertas na primeira vez quando a página for carregada
//document.addEventListener('DOMContentLoaded', carregarUltimosAlertas);