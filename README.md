# -SafeGuardX
achei uma falha numa empresa onde eu trabalho

Durante atuação em ambiente de telemarketing, utilizando sistemas corporativos de atendimento ao cliente (CRM e plataformas internas), foi identificado um possível risco de segurança relacionado ao uso de navegadores.

O ambiente permitia o uso de extensões do Google Chrome sem restrições adequadas.

⚠️ Vulnerabilidade Identificada

A falha consistia na:

Permissão irrestrita para instalação de extensões no navegador corporativo

Isso possibilitava que usuários instalassem ferramentas externas, incluindo:

Ambientes Linux via navegador (máquinas virtuais online)
Extensões com acesso a páginas e dados exibidos
🧪 Prova de Conceito (PoC - Controlada)

Foi utilizada uma extensão que permitia acesso a um ambiente Linux virtual dentro do navegador.

Com isso, teoricamente seria possível:

Interagir com dados exibidos na tela
Criar scripts ou capturas automatizadas
Manipular informações dentro da sessão ativa
🔥 Impacto Potencial

Caso explorada de forma maliciosa, a vulnerabilidade poderia expor:

CPF de clientes
Nome completo
Telefones
E-mails
Endereços
Informações financeiras (ex: limite de cartão)
Dados pessoais adicionais

👉 Ou seja: exposição total de dados sensíveis (LGPD)

🚨 Risco
Vazamento de dados
Acesso não autorizado
Possível fraude
Comprometimento da empresa
✅ Mitigação (o que foi feito)

Após o reporte:

Bloqueio de extensões no navegador
Restrição de ambientes externos
Ajustes na política de rede
🧠 Conclusão

A vulnerabilidade não estava nos sistemas principais, mas sim na:

falta de controle do ambiente do usuário (endpoint security)

Esse tipo de falha é comum e muitas vezes negligenciado.


⚖️ Ética

A vulnerabilidade foi:

Identificada durante atividades normais de trabalho
Testada de forma controlada e sem causar danos
Sem acesso indevido a dados além do necessário para validação
Sem compartilhamento de informações sensíveis

Após a confirmação, foi:

Reportada internamente aos responsáveis
Tratada seguindo boas práticas de segurança
Corrigida pela equipe responsável

👉 Todo o processo seguiu princípios de responsabilidade, confidencialidade e boa-fé, com o objetivo exclusivo de melhorar a segurança do ambiente.
Eu criei um script para analisar o seu pc se ele tem virus ou nao

🏷️ Classificação
Tipo: Falha de configuração (Misconfiguration)
Categoria: Endpoint Security
Severidade: Alta

lembrando esse codigo e para linux
