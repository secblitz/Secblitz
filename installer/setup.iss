; Compile through scripts/build-release.ps1 (Inno Setup 6.7.3 or later).
#ifndef AppVersion
  #error AppVersion must be supplied by build-release.ps1
#endif
#ifndef SourceExe
  #error SourceExe must be supplied by build-release.ps1
#endif
#ifndef Arch
  #define Arch "x64"
#endif
#if Arch != "x64" && Arch != "arm64"
  #error Arch must be x64 or arm64
#endif
#ifndef OutputPath
  #define OutputPath "..\dist"
#endif
#if Ver < EncodeVer(6, 7, 3)
  #error Secblitz needs Inno Setup 6.7.3 or later. Run scripts/install-inno.ps1.
#endif

[Setup]
AppId={{30C8385C-D114-44DD-868B-45C469D690BC}
AppName=Secblitz
AppVersion={#AppVersion}
AppPublisher=Secblitz
AppPublisherURL=https://secblitz.lol
AppSupportURL=https://secblitz.lol
AppUpdatesURL=https://secblitz.lol
AppCopyright=Copyright 2026 Secblitz contributors. MIT License.
; Plain file details for Setup itself (Properties, security prompts).
VersionInfoVersion={#AppVersion}
VersionInfoProductVersion={#AppVersion}
VersionInfoProductTextVersion={#AppVersion}
VersionInfoTextVersion={#AppVersion}
VersionInfoCompany=Secblitz
VersionInfoDescription=Secblitz Setup
VersionInfoProductName=Secblitz
VersionInfoCopyright=Copyright 2026 Secblitz contributors. MIT License.
DefaultDirName={autopf64}\Secblitz
DisableDirPage=yes
UsePreviousAppDir=no
DisableProgramGroupPage=yes
PrivilegesRequired=admin
#if Arch == "arm64"
ArchitecturesAllowed=arm64
ArchitecturesInstallIn64BitMode=arm64
#else
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#endif
MinVersion=10.0
WizardStyle=modern dynamic hidebevels
; The banner adds height, so the pages keep their usual height rather than the modern 120%.
WizardSizePercent=120,100
DisableWelcomePage=no
DisableReadyPage=yes
WizardImageFile=
WizardSmallImageFile=
SetupIconFile=..\assets\secblitz.ico
UninstallDisplayIcon={app}\secblitz.exe
OutputDir={#OutputPath}
OutputBaseFilename=secblitz-{#AppVersion}-windows-{#Arch}-setup
Compression=lzma2
SolidCompression=yes
; The tray agent answers WM_QUERYENDSESSION/WM_ENDSESSION/WM_CLOSE by exiting, so
; Restart Manager can close it. Updates also signal it through the quiesce event.
CloseApplications=yes
CloseApplicationsFilter=secblitz.exe
RestartApplications=no
ChangesAssociations=no
UsePreviousTasks=no
SetupMutex=Global\SecblitzSetup
Uninstallable=yes
#ifdef SignToolName
SignTool={#SignToolName}
SignedUninstaller=yes
#endif

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "fr"; MessagesFile: "compiler:Languages\French.isl"
Name: "de"; MessagesFile: "compiler:Languages\German.isl"
Name: "pt"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"
Name: "it"; MessagesFile: "compiler:Languages\Italian.isl"

[CustomMessages]
en.AutoUpdates=Keep Secblitz up to date automatically (checks every hour)
es.AutoUpdates=Mantener Secblitz actualizado automáticamente (comprueba cada hora)
fr.AutoUpdates=Maintenir Secblitz à jour automatiquement (vérification toutes les heures)
de.AutoUpdates=Secblitz automatisch aktuell halten (prüft jede Stunde)
pt.AutoUpdates=Manter o Secblitz atualizado automaticamente (verifica a cada hora)
it.AutoUpdates=Mantieni Secblitz aggiornato automaticamente (controlla ogni ora)
en.PrivacyTitle=Your privacy
es.PrivacyTitle=Tu privacidad
fr.PrivacyTitle=Votre vie privée
de.PrivacyTitle=Deine Privatsphäre
pt.PrivacyTitle=Sua privacidade
it.PrivacyTitle=La tua privacy
en.PrivacySubtitle=What Secblitz does with your information
es.PrivacySubtitle=Qué hace Secblitz con tu información
fr.PrivacySubtitle=Ce que Secblitz fait de vos informations
de.PrivacySubtitle=Was Secblitz mit Deinen Daten macht
pt.PrivacySubtitle=O que o Secblitz faz com as suas informações
it.PrivacySubtitle=Cosa fa Secblitz con le tue informazioni
en.PrivacyText=Secblitz has no account, no ads and no tracking. Your results stay on your PC.%n%nIt goes online only to keep itself up to date and for things you ask for, such as installing an app. You can turn automatic updates off on the next page.%n%nIf you switch on web protection later in the app, Secblitz downloads block lists and passes your website lookups on. Details are in the privacy policy.%n%nThe full privacy policy is at secblitz.lol/privacy.html.
es.PrivacyText=Secblitz no tiene cuenta, ni anuncios, ni seguimiento. Tus resultados se quedan en tu PC.%n%nSolo se conecta a internet para mantenerse actualizado y para lo que tú le pidas, como instalar una app. Puedes desactivar las actualizaciones automáticas en la página siguiente.%n%nSi activas más tarde la protección web en la app, Secblitz descarga listas de bloqueo y pasa tus consultas de sitios web a otros servidores. Los detalles están en la política de privacidad.%n%nLa política de privacidad completa está en secblitz.lol/privacy.html.
fr.PrivacyText=Secblitz n'a ni compte, ni publicité, ni suivi. Vos résultats restent sur votre PC.%n%nIl ne se connecte à Internet que pour se tenir à jour et pour ce que vous lui demandez, comme installer une application. Vous pouvez désactiver les mises à jour automatiques à la page suivante.%n%nSi vous activez plus tard la protection web dans l'application, Secblitz télécharge des listes de blocage et transmet vos recherches de sites web à d'autres serveurs. Les détails figurent dans la politique de confidentialité.%n%nLa politique de confidentialité complète se trouve sur secblitz.lol/privacy.html.
de.PrivacyText=Secblitz hat kein Konto, keine Werbung und kein Tracking. Deine Ergebnisse bleiben auf Deinem PC.%n%nEs geht nur online, um sich aktuell zu halten und für Dinge, um die Du es bittest, etwa eine App zu installieren. Automatische Updates kannst Du auf der nächsten Seite ausschalten.%n%nWenn Du den Webschutz später in der App einschaltest, lädt Secblitz Sperrlisten herunter und gibt die Namen der Websites, die Du aufrufst, an andere Server weiter. Einzelheiten stehen in der Datenschutzerklärung.%n%nDie vollständige Datenschutzerklärung findest Du unter secblitz.lol/privacy.html.
pt.PrivacyText=O Secblitz não tem conta, anúncios nem rastreamento. Seus resultados ficam no seu PC.%n%nEle só se conecta à internet para se manter atualizado e para o que você pedir, como instalar um app. Você pode desativar as atualizações automáticas na próxima página.%n%nSe você ativar a proteção da web mais tarde no app, o Secblitz baixa listas de bloqueio e repassa suas consultas de sites. Os detalhes estão na política de privacidade.%n%nA política de privacidade completa está em secblitz.lol/privacy.html.
it.PrivacyText=Secblitz non ha account, pubblicità né tracciamento. I tuoi risultati restano sul tuo PC.%n%nSi collega a internet solo per tenersi aggiornato e per ciò che gli chiedi, come installare un'app. Puoi disattivare gli aggiornamenti automatici nella pagina successiva.%n%nSe attivi più tardi la protezione web nell'app, Secblitz scarica elenchi di blocco e inoltra le tue richieste di siti web. I dettagli sono nell'informativa sulla privacy.%n%nL'informativa completa sulla privacy è su secblitz.lol/privacy.html.
en.DesktopIcon=Keep Secblitz handy - create a desktop shortcut
es.DesktopIcon=Ten Secblitz a mano: crea un acceso directo en el escritorio
fr.DesktopIcon=Gardez Secblitz à portée de main : créez un raccourci sur le bureau
de.DesktopIcon=Secblitz griffbereit halten – Desktop-Verknüpfung erstellen
pt.DesktopIcon=Tenha o Secblitz à mão - criar um atalho na área de trabalho
it.DesktopIcon=Secblitz a portata di mano: crea un collegamento sul desktop
en.LaunchSecblitz=Open Secblitz
es.LaunchSecblitz=Abrir Secblitz
fr.LaunchSecblitz=Ouvrir Secblitz
de.LaunchSecblitz=Secblitz öffnen
pt.LaunchSecblitz=Abrir o Secblitz
it.LaunchSecblitz=Apri Secblitz
en.TrayIcon=Show the Secblitz shield in the taskbar corner
es.TrayIcon=Mostrar el escudo de Secblitz en la esquina de la barra de tareas
fr.TrayIcon=Afficher le bouclier Secblitz dans le coin de la barre des tâches
de.TrayIcon=Secblitz-Schild in der Ecke der Taskleiste anzeigen
pt.TrayIcon=Mostrar o escudo do Secblitz no canto da barra de tarefas
it.TrayIcon=Mostra lo scudo di Secblitz nell'angolo della barra delle applicazioni
en.Monitor=Check my PC automatically in the background
es.Monitor=Comprobar mi PC automáticamente en segundo plano
fr.Monitor=Vérifier mon PC automatiquement en arrière-plan
de.Monitor=Meinen PC automatisch im Hintergrund prüfen
pt.Monitor=Verificar meu PC automaticamente em segundo plano
it.Monitor=Controlla il mio PC automaticamente in background
en.Failed=Secblitz could not finish setting up. Restart your PC and run the installer again. If it still does not work, download the latest Secblitz and try again.
es.Failed=Secblitz no pudo terminar la instalación. Reinicia tu PC y vuelve a ejecutar el instalador. Si sigue sin funcionar, descarga la última versión de Secblitz e inténtalo de nuevo.
fr.Failed=Secblitz n'a pas pu terminer l'installation. Redémarrez votre PC et relancez l'installateur. Si cela ne fonctionne toujours pas, téléchargez la dernière version de Secblitz et réessayez.
de.Failed=Secblitz konnte die Einrichtung nicht abschließen. Starte Deinen PC neu und führe das Installationsprogramm erneut aus. Falls es weiterhin nicht klappt, lade die neueste Version von Secblitz herunter und versuche es noch einmal.
pt.Failed=O Secblitz não conseguiu terminar a instalação. Reinicie o PC e execute o instalador de novo. Se ainda não funcionar, baixe a versão mais recente do Secblitz e tente novamente.
it.Failed=Secblitz non è riuscito a completare l'installazione. Riavvia il PC ed esegui di nuovo il programma di installazione. Se continua a non funzionare, scarica l'ultima versione di Secblitz e riprova.
en.RemoveTitle=Remove Secblitz
es.RemoveTitle=Quitar Secblitz
fr.RemoveTitle=Supprimer Secblitz
de.RemoveTitle=Secblitz entfernen
pt.RemoveTitle=Remover o Secblitz
it.RemoveTitle=Rimuovi Secblitz
en.RemoveQuestion=What should happen to the changes Secblitz made?
es.RemoveQuestion=¿Qué debe pasar con los cambios que hizo Secblitz?
fr.RemoveQuestion=Que faire des modifications effectuées par Secblitz ?
de.RemoveQuestion=Was soll mit den Änderungen geschehen, die Secblitz vorgenommen hat?
pt.RemoveQuestion=O que deve acontecer com as alterações feitas pelo Secblitz?
it.RemoveQuestion=Cosa deve succedere alle modifiche fatte da Secblitz?
en.KeepChoice=Keep my PC as it is now
es.KeepChoice=Dejar mi PC como está ahora
fr.KeepChoice=Laisser mon PC tel qu'il est maintenant
de.KeepChoice=Meinen PC so lassen, wie er jetzt ist
pt.KeepChoice=Manter meu PC como está agora
it.KeepChoice=Lascia il mio PC com'è adesso
en.KeepDetail=Your protection stays on, and apps you removed stay removed. Their saved copies are deleted, so apps that are not in the Microsoft Store can't come back. Bring back any you want first in Clean up apps.
es.KeepDetail=Tu protección sigue activa y las apps que quitaste siguen quitadas. Sus copias guardadas se borran, así que las apps que no están en Microsoft Store no podrán volver. Recupera primero las que quieras en Limpiar aplicaciones.
fr.KeepDetail=Votre protection reste active et les applications que vous avez supprimées restent supprimées. Leurs copies enregistrées sont effacées : les applications absentes du Microsoft Store ne pourront plus revenir. Récupérez d'abord celles que vous voulez dans Nettoyer les applications.
de.KeepDetail=Dein Schutz bleibt eingeschaltet, und Apps, die Du entfernt hast, bleiben entfernt. Ihre gespeicherten Kopien werden gelöscht, daher lassen sich Apps, die es nicht im Microsoft Store gibt, nicht mehr zurückholen. Hol gewünschte Apps vorher unter Apps aufräumen zurück.
pt.KeepDetail=Sua proteção continua ativada e os apps que você removeu continuam removidos. As cópias guardadas são apagadas, então os apps que não estão na Microsoft Store não poderão voltar. Recupere antes os que quiser em Limpar apps.
it.KeepDetail=La tua protezione resta attiva e le app che hai rimosso restano rimosse. Le copie salvate vengono eliminate, quindi le app che non sono nel Microsoft Store non potranno tornare. Recupera prima quelle che vuoi in Pulisci le app.
en.PutBackChoice=Put everything back the way it was
es.PutBackChoice=Devolver todo a como estaba
fr.PutBackChoice=Tout remettre comme avant
de.PutBackChoice=Alles wieder so machen, wie es war
pt.PutBackChoice=Voltar tudo como estava
it.PutBackChoice=Rimetti tutto com'era
en.PutBackDetail=Secblitz undoes its changes and brings back the apps you removed first. This can take a few minutes.
es.PutBackDetail=Primero Secblitz deshace sus cambios y recupera las apps que quitaste. Esto puede tardar unos minutos.
fr.PutBackDetail=Secblitz commence par annuler ses modifications et récupérer les applications que vous avez supprimées. Cela peut prendre quelques minutes.
de.PutBackDetail=Secblitz macht zuerst seine Änderungen rückgängig und holt die Apps zurück, die Du entfernt hast. Das kann einige Minuten dauern.
pt.PutBackDetail=O Secblitz primeiro desfaz suas alterações e traz de volta os apps que você removeu. Isso pode levar alguns minutos.
it.PutBackDetail=Prima Secblitz annulla le sue modifiche e recupera le app che hai rimosso. Può richiedere alcuni minuti.
en.RemoveNote=Windows updates, virus scans and apps you installed with Secblitz stay.
es.RemoveNote=Las actualizaciones de Windows, los análisis de virus y las apps que instalaste con Secblitz se quedan.
fr.RemoveNote=Les mises à jour Windows, les analyses antivirus et les applications installées avec Secblitz sont conservées.
de.RemoveNote=Windows-Updates, Virenscans und mit Secblitz installierte Apps bleiben erhalten.
pt.RemoveNote=As atualizações do Windows, as verificações de vírus e os apps que você instalou com o Secblitz permanecem.
it.RemoveNote=Gli aggiornamenti di Windows, le scansioni antivirus e le app installate con Secblitz restano.
en.WebStops=Web protection stops too, because it is part of Secblitz.
es.WebStops=La protección web también se detiene, porque forma parte de Secblitz.
fr.WebStops=La protection web s’arrête aussi, car elle fait partie de Secblitz.
de.WebStops=Der Webschutz endet ebenfalls, weil er Teil von Secblitz ist.
pt.WebStops=A proteção da web também para, porque faz parte do Secblitz.
it.WebStops=Anche la protezione web si ferma, perché fa parte di Secblitz.
en.PuttingBack=Putting your settings back
es.PuttingBack=Restaurando tus ajustes
fr.PuttingBack=Rétablissement de vos paramètres
de.PuttingBack=Deine Einstellungen werden zurückgesetzt
pt.PuttingBack=Restaurando suas configurações
it.PuttingBack=Ripristino delle tue impostazioni
en.LeftIntro=Some things could not be put back. They stay as they are:
es.LeftIntro=Algunas cosas no se pudieron restaurar. Se quedan como están:
fr.LeftIntro=Certaines choses n'ont pas pu être rétablies. Elles restent telles quelles :
de.LeftIntro=Einiges ließ sich nicht zurücksetzen. Es bleibt so, wie es ist:
pt.LeftIntro=Algumas coisas não puderam ser restauradas. Elas continuam como estão:
it.LeftIntro=Alcune cose non è stato possibile ripristinarle. Restano come sono:
en.PersonalLeft=Some of your personal settings could not be put back. You can change them yourself in Windows Settings.
es.PersonalLeft=Algunos de tus ajustes personales no se pudieron restaurar. Puedes cambiarlos tú mismo en Configuración de Windows.
fr.PersonalLeft=Certains de vos paramètres personnels n'ont pas pu être rétablis. Vous pouvez les modifier vous-même dans les Paramètres de Windows.
de.PersonalLeft=Einige Deiner persönlichen Einstellungen ließen sich nicht zurücksetzen. Du kannst sie selbst in den Windows-Einstellungen ändern.
pt.PersonalLeft=Algumas das suas configurações pessoais não puderam ser restauradas. Você mesmo pode alterá-las nas Configurações do Windows.
it.PersonalLeft=Alcune delle tue impostazioni personali non è stato possibile ripristinarle. Puoi modificarle tu stesso nelle Impostazioni di Windows.
en.SettingsLeft=Some Windows settings could not be put back. You can change them yourself in Windows Settings.
en.RemoveFailed=Secblitz could not be removed, and nothing was changed. Restart your PC and try again. If it still does not work, open Secblitz and check for an update.
en.FixedFolder=Secblitz can only be installed in its standard folder inside Program Files. Please keep the suggested folder and try again.
es.SettingsLeft=Algunos ajustes de Windows no se pudieron restaurar. Puedes cambiarlos tú mismo en Configuración de Windows.
es.RemoveFailed=No se pudo quitar Secblitz y no se cambió nada. Reinicia tu PC e inténtalo de nuevo. Si sigue sin funcionar, abre Secblitz y busca una actualización.
es.FixedFolder=Secblitz solo se puede instalar en su carpeta estándar dentro de Archivos de programa. Mantén la carpeta sugerida e inténtalo de nuevo.
fr.SettingsLeft=Certains paramètres de Windows n'ont pas pu être rétablis. Vous pouvez les modifier vous-même dans les Paramètres de Windows.
fr.RemoveFailed=Secblitz n'a pas pu être supprimé et rien n'a été modifié. Redémarrez votre PC et réessayez. Si cela ne fonctionne toujours pas, ouvrez Secblitz et recherchez une mise à jour.
fr.FixedFolder=Secblitz ne peut être installé que dans son dossier standard de Program Files. Gardez le dossier proposé et réessayez.
de.SettingsLeft=Einige Windows-Einstellungen ließen sich nicht zurücksetzen. Du kannst sie selbst in den Windows-Einstellungen ändern.
de.RemoveFailed=Secblitz konnte nicht entfernt werden, und es wurde nichts geändert. Starte Deinen PC neu und versuche es noch einmal. Falls es weiterhin nicht klappt, öffne Secblitz und suche nach einem Update.
de.FixedFolder=Secblitz kann nur in seinem Standardordner unter Programme installiert werden. Behalte den vorgeschlagenen Ordner bei und versuche es noch einmal.
pt.SettingsLeft=Algumas configurações do Windows não puderam ser restauradas. Você mesmo pode alterá-las nas Configurações do Windows.
pt.RemoveFailed=Não foi possível remover o Secblitz e nada foi alterado. Reinicie o PC e tente novamente. Se ainda não funcionar, abra o Secblitz e procure uma atualização.
pt.FixedFolder=O Secblitz só pode ser instalado na pasta padrão dentro de Arquivos de Programas. Mantenha a pasta sugerida e tente novamente.
it.SettingsLeft=Alcune impostazioni di Windows non è stato possibile ripristinarle. Puoi modificarle tu stesso nelle Impostazioni di Windows.
it.RemoveFailed=Non è stato possibile rimuovere Secblitz e non è stato modificato nulla. Riavvia il PC e riprova. Se continua a non funzionare, apri Secblitz e cerca un aggiornamento.
it.FixedFolder=Secblitz può essere installato solo nella sua cartella standard in Programmi. Mantieni la cartella suggerita e riprova.

[Messages]
en.WelcomeLabel1=Install Secblitz
es.WelcomeLabel1=Instalar Secblitz
fr.WelcomeLabel1=Installer Secblitz
de.WelcomeLabel1=Secblitz installieren
pt.WelcomeLabel1=Instalar o Secblitz
it.WelcomeLabel1=Installa Secblitz
en.WelcomeLabel2=Secblitz checks how safe and private your PC is, and fixes what you choose. Nothing changes until you say yes.%n%nSetup takes about a minute. Your apps stay open and your PC does not restart.
es.WelcomeLabel2=Secblitz revisa qué tan seguro y privado es tu PC y corrige lo que tú elijas. No cambia nada hasta que digas que sí.%n%nLa instalación tarda cerca de un minuto. Tus aplicaciones siguen abiertas y tu PC no se reinicia.
fr.WelcomeLabel2=Secblitz vérifie la sécurité et la confidentialité de votre PC et corrige ce que vous choisissez. Rien ne change tant que vous n'avez pas dit oui.%n%nL'installation dure environ une minute. Vos applications restent ouvertes et votre PC ne redémarre pas.
de.WelcomeLabel2=Secblitz prüft, wie sicher und privat Dein PC ist, und behebt, was Du auswählst. Nichts ändert sich, bevor Du Ja sagst.%n%nDie Installation dauert etwa eine Minute. Deine Apps bleiben geöffnet und Dein PC startet nicht neu.
pt.WelcomeLabel2=O Secblitz verifica o quanto o seu PC é seguro e privado e corrige o que você escolher. Nada muda até você dizer sim.%n%nA instalação leva cerca de um minuto. Seus aplicativos continuam abertos e o PC não reinicia.
it.WelcomeLabel2=Secblitz controlla quanto è sicuro e privato il tuo PC e corregge ciò che scegli tu. Non cambia nulla finché non dici di sì.%n%nL'installazione richiede circa un minuto. Le tue app restano aperte e il PC non si riavvia.
en.WizardSelectTasks=Choose what you want
es.WizardSelectTasks=Elige lo que quieres
fr.WizardSelectTasks=Choisissez ce que vous voulez
de.WizardSelectTasks=Wähle, was Du möchtest
pt.WizardSelectTasks=Escolha o que você quer
it.WizardSelectTasks=Scegli cosa vuoi
en.SelectTasksDesc=Untick anything you don't want.
es.SelectTasksDesc=Desmarca lo que no quieras.
fr.SelectTasksDesc=Décochez ce que vous ne voulez pas.
de.SelectTasksDesc=Entferne den Haken bei allem, was Du nicht möchtest.
pt.SelectTasksDesc=Desmarque o que você não quiser.
it.SelectTasksDesc=Deseleziona ciò che non vuoi.
en.SelectTasksLabel2=Tick or untick the extras below, then click Next.
es.SelectTasksLabel2=Marca o desmarca los extras de abajo y haz clic en Siguiente.
fr.SelectTasksLabel2=Cochez ou décochez les options ci-dessous, puis cliquez sur Suivant.
de.SelectTasksLabel2=Setze oder entferne die Haken bei den Extras unten und klicke auf Weiter.
pt.SelectTasksLabel2=Marque ou desmarque os extras abaixo e clique em Avançar.
it.SelectTasksLabel2=Seleziona o deseleziona gli extra qui sotto e fai clic su Avanti.
en.FinishedHeadingLabel=Secblitz is ready
es.FinishedHeadingLabel=Secblitz está listo
fr.FinishedHeadingLabel=Secblitz est prêt
de.FinishedHeadingLabel=Secblitz ist bereit
pt.FinishedHeadingLabel=O Secblitz está pronto
it.FinishedHeadingLabel=Secblitz è pronto
en.FinishedLabel=Open it and run your first check. Nothing changes until you say yes.
es.FinishedLabel=Ábrelo y haz tu primera revisión. No cambia nada hasta que digas que sí.
fr.FinishedLabel=Ouvrez-le et lancez votre première vérification. Rien ne change tant que vous n'avez pas dit oui.
de.FinishedLabel=Öffne es und starte Deine erste Prüfung. Nichts ändert sich, bevor Du Ja sagst.
pt.FinishedLabel=Abra-o e faça sua primeira verificação. Nada muda até você dizer sim.
it.FinishedLabel=Aprilo e fai il primo controllo. Non cambia nulla finché non dici di sì.
en.FinishedLabelNoIcons=Open it and run your first check. Nothing changes until you say yes.
es.FinishedLabelNoIcons=Ábrelo y haz tu primera revisión. No cambia nada hasta que digas que sí.
fr.FinishedLabelNoIcons=Ouvrez-le et lancez votre première vérification. Rien ne change tant que vous n'avez pas dit oui.
de.FinishedLabelNoIcons=Öffne es und starte Deine erste Prüfung. Nichts ändert sich, bevor Du Ja sagst.
pt.FinishedLabelNoIcons=Abra-o e faça sua primeira verificação. Nada muda até você dizer sim.
it.FinishedLabelNoIcons=Aprilo e fai il primo controllo. Non cambia nulla finché non dici di sì.
en.InstallingLabel=Secblitz is installing. This takes about a minute.
es.InstallingLabel=Secblitz se está instalando. Tarda alrededor de un minuto.
fr.InstallingLabel=Secblitz est en cours d'installation. Cela prend environ une minute.
de.InstallingLabel=Secblitz wird installiert. Das dauert etwa eine Minute.
pt.InstallingLabel=O Secblitz está sendo instalado. Isso leva cerca de um minuto.
it.InstallingLabel=Secblitz è in fase di installazione. Ci vuole circa un minuto.
en.ClickFinish=Click Finish to close Setup.
es.ClickFinish=Haz clic en Finalizar para cerrar el instalador.
fr.ClickFinish=Cliquez sur Terminer pour fermer l'installation.
de.ClickFinish=Klicke auf "Fertigstellen", um das Setup zu schließen.
pt.ClickFinish=Clique em Concluir para fechar o instalador.
it.ClickFinish=Fai clic su Fine per chiudere l'installazione.
en.ConfirmUninstall=Do you want to remove %1 from this PC?
es.ConfirmUninstall=¿Quieres quitar %1 de este PC?
fr.ConfirmUninstall=Voulez-vous supprimer %1 de ce PC ?
de.ConfirmUninstall=Möchtest Du %1 von diesem PC entfernen?
pt.ConfirmUninstall=Deseja remover o %1 deste PC?
it.ConfirmUninstall=Vuoi rimuovere %1 da questo PC?

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopIcon}"; Check: DesktopDefault
Name: "desktopicon"; Description: "{cm:DesktopIcon}"; Flags: unchecked; Check: DesktopOptedOut
Name: "trayicon"; Description: "{cm:TrayIcon}"
Name: "monitor"; Description: "{cm:Monitor}"; Flags: unchecked
Name: "autoupdates"; Description: "{cm:AutoUpdates}"; Check: AutoUpdatesDefault
Name: "autoupdates"; Description: "{cm:AutoUpdates}"; Flags: unchecked; Check: AutoUpdatesOptedOut

[Files]
Source: "{#SourceExe}"; DestDir: "{app}"; DestName: "secblitz.exe"; Flags: ignoreversion
Source: "art\banner-*.png"; Flags: dontcopy
; Uninstall cannot extract temporary files, so the Remove Secblitz window reads its banner from here.
Source: "art\banner-*.png"; DestDir: "{app}\art"; Flags: ignoreversion

[Registry]
; Per-machine logon entry for the unelevated tray agent; removed on uninstall.
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "SecblitzTray"; ValueData: """{app}\secblitz.exe"" tray"; Flags: uninsdeletevalue; Tasks: trayicon

[Icons]
; Ordinary launch: the application's asInvoker manifest and UAC flow own elevation.
Name: "{commonprograms}\Secblitz"; Filename: "{app}\secblitz.exe"; WorkingDir: "{app}"
Name: "{commondesktop}\Secblitz"; Filename: "{app}\secblitz.exe"; WorkingDir: "{app}"; Tasks: desktopicon

; Inno creates/removes the owned .lnk. No wildcard; only the fixed Status
; directory (tray status file written by the monitor/app) is removed.
[UninstallDelete]
Type: filesandordirs; Name: "{app}\Status"
Type: filesandordirs; Name: "{app}\art"
; Setup records the program folder only when it creates it; an install into a
; folder that already existed would otherwise leave it behind, empty.
Type: dirifempty; Name: "{app}"

[Run]
; Start Setup normally so Inno retains the original unelevated user context.
; runasoriginaluser cannot de-elevate an already-elevated Setup invocation.
Filename: "{app}\secblitz.exe"; WorkingDir: "{app}"; Description: "{cm:LaunchSecblitz}"; Flags: nowait postinstall skipifsilent runasoriginaluser; Check: CanLaunchSecblitz
; Start the tray right away for the person who ran Setup (not for silent updates,
; where the update worker restarts it in each session that had one).
Filename: "{app}\secblitz.exe"; Parameters: "tray"; WorkingDir: "{app}"; Flags: nowait skipifsilent runasoriginaluser; Tasks: trayicon; Check: CanLaunchSecblitz

[Code]
{ Embed the maintenance source in both Setup and Uninstall. Never execute a
  pre-existing script from the installation directory before validating it. }
const MaintenanceSource =
#define MaintenanceHandle
#define MaintenanceLine
#sub EmitMaintenanceLine
  #define MaintenanceLine = FileRead(MaintenanceHandle)
  #emit "'" + StringChange(MaintenanceLine, "'", "''") + "' + #13#10 +"
#endsub
#for {MaintenanceHandle = FileOpen(AddBackslash(SourcePath) + "maintenance.ps1"); MaintenanceHandle && !FileEof(MaintenanceHandle); ""} EmitMaintenanceLine
#if MaintenanceHandle
  #expr FileClose(MaintenanceHandle)
#else
  #error Cannot read maintenance.ps1
#endif
'';

var ResumeAfterUpgrade, ResumeFilterAfterUpgrade, PostInstallFailed: Boolean;
    UninstallPutBack: Boolean;
    PreviousDesktopSelected, PreviousAutoUpdatesEnabled, PreviousHasUpdatePreference: Boolean;
    PrivacyPage: TOutputMsgWizardPage;

const SM_CYMAXIMIZED = 62;

function GetSystemMetrics(Index: Integer): Integer;
  external 'GetSystemMetrics@user32.dll stdcall';

{ The smallest banner at least as wide as the space it fills, so it is never stretched up. }
function BannerWidth(Width: Integer): Integer;
begin
  if Width <= 600 then Result := 600
  else if Width <= 750 then Result := 750
  else if Width <= 900 then Result := 900
  else if Width <= 1050 then Result := 1050
  else if Width <= 1200 then Result := 1200
  else Result := 1500;
end;

{ Puts the banner across the top of Parent and returns its height, or 0 when none is shown.
  Banners are 3.8 times wider than tall. FromFolder is empty in Setup (the files are unpacked
  from the installer) and the installed art folder in Uninstall. }
function AddBanner(Parent: TWinControl; FromFolder: String; Width: Integer): Integer;
var
  Image: TBitmapImage;
  Theme, Name: String;
begin
  Result := 0;
  if HighContrastActive then Exit;
  if IsDarkInstallMode then Theme := 'dark' else Theme := 'light';
  Name := 'banner-' + Theme + '-' + IntToStr(BannerWidth(Width)) + '.png';
  try
    if FromFolder = '' then begin
      ExtractTemporaryFile(Name);
      FromFolder := ExpandConstant('{tmp}');
    end;
    FromFolder := AddBackslash(FromFolder);
    if not FileExists(FromFolder + Name) then Exit;
    Image := TBitmapImage.Create(Parent);
    Image.Stretch := True;
    Image.PngImage.LoadFromFile(FromFolder + Name);
    Image.Parent := Parent;
    Result := (Width * 5 + 9) div 19;
    Image.SetBounds(0, 0, Width, Result);
  except
    Result := 0;
  end;
end;

procedure InitializeWizard;
var Enabled: Cardinal; BannerHeight, Grow, TasksTop: Integer;
begin
  { Snapshot while the previous uninstall data is still available. Inno replaces
    that data before RegisterPreviousData, so that callback must not reread it. }
  PreviousDesktopSelected := GetPreviousData('DesktopSelected', '1') = '1';
  PreviousHasUpdatePreference := RegQueryDWordValue(HKLM64, 'Software\Secblitz', 'AutoUpdatesEnabled', Enabled);
  PreviousAutoUpdatesEnabled := True;
  if PreviousHasUpdatePreference then PreviousAutoUpdatesEnabled := Enabled <> 0;
  PrivacyPage := CreateOutputMsgPage(wpWelcome, CustomMessage('PrivacyTitle'),
    CustomMessage('PrivacySubtitle'), CustomMessage('PrivacyText'));
  { The banner replaces the header strip and the side images, so the pages are pushed down
    and the text may use the full width. Changing the form's height first lets the anchored
    buttons follow; the page area is then moved down and shortened by the banner's height. }
  BannerHeight := AddBanner(WizardForm, '', WizardForm.ClientWidth);
  if BannerHeight > 0 then begin
    { On a short screen the window only grows as far as a maximized window would reach. }
    Grow := GetSystemMetrics(SM_CYMAXIMIZED) - WizardForm.Height;
    if Grow > BannerHeight then Grow := BannerHeight;
    if Grow < 0 then Grow := 0;
    WizardForm.ClientHeight := WizardForm.ClientHeight + Grow;
    WizardForm.OuterNotebook.Top := WizardForm.OuterNotebook.Top + BannerHeight;
    WizardForm.OuterNotebook.Height := WizardForm.OuterNotebook.Height - BannerHeight;
    WizardForm.WizardSmallBitmapImage.Visible := False;
    WizardForm.PageNameLabel.Width := WizardForm.MainPanel.ClientWidth - WizardForm.PageNameLabel.Left * 2;
    WizardForm.PageDescriptionLabel.Width := WizardForm.PageNameLabel.Width;
    WizardForm.WizardBitmapImage.Visible := False;
    WizardForm.WizardBitmapImage2.Visible := False;
    WizardForm.WelcomeLabel1.Left := ScaleX(28);
    WizardForm.WelcomeLabel1.Width := WizardForm.WelcomePage.ClientWidth - ScaleX(56);
    WizardForm.WelcomeLabel2.Left := ScaleX(28);
    WizardForm.WelcomeLabel2.Width := WizardForm.WelcomeLabel1.Width;
    WizardForm.FinishedHeadingLabel.Left := ScaleX(28);
    WizardForm.FinishedHeadingLabel.Width := WizardForm.FinishedPage.ClientWidth - ScaleX(56);
    WizardForm.FinishedLabel.Left := ScaleX(28);
    WizardForm.FinishedLabel.Width := WizardForm.FinishedHeadingLabel.Width;
    WizardForm.WelcomeLabel1.AdjustHeight;
    WizardForm.WelcomeLabel2.Top := WizardForm.WelcomeLabel1.Top + WizardForm.WelcomeLabel1.Height + ScaleY(12);
    WizardForm.WelcomeLabel2.AdjustHeight;
    WizardForm.FinishedHeadingLabel.AdjustHeight;
    WizardForm.FinishedLabel.Top := WizardForm.FinishedHeadingLabel.Top + WizardForm.FinishedHeadingLabel.Height + ScaleY(12);
    WizardForm.FinishedLabel.AdjustHeight;
    { Inno places RunList under FinishedLabel itself when the page opens, measured from YesRadio. }
    WizardForm.RunList.Left := ScaleX(28);
    WizardForm.RunList.Width := WizardForm.FinishedHeadingLabel.Width;
    TasksTop := WizardForm.SelectTasksLabel.Top;
    WizardForm.SelectTasksLabel.Visible := False;
    WizardForm.TasksList.Height := WizardForm.TasksList.Height + WizardForm.TasksList.Top - TasksTop;
    WizardForm.TasksList.Top := TasksTop;
  end;
end;

{ The Ready page is skipped, so this click installs. }
procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpSelectTasks then
    WizardForm.NextButton.Caption := SetupMessage(msgButtonInstall);
end;

function DesktopDefault: Boolean;
begin
  Result := PreviousDesktopSelected;
end;

function DesktopOptedOut: Boolean;
begin
  Result := not DesktopDefault;
end;

procedure RegisterPreviousData(PreviousDataKey: Integer);
var DesktopSelected: Boolean;
begin
  { Automatic upgrades suppress optional tasks, not the saved desktop choice. }
  if ExpandConstant('{param:SECBLITZUPDATE|0}') = '1' then
    DesktopSelected := PreviousDesktopSelected
  else
    DesktopSelected := WizardIsTaskSelected('desktopicon');
  if DesktopSelected then
    SetPreviousData(PreviousDataKey, 'DesktopSelected', '1')
  else
    SetPreviousData(PreviousDataKey, 'DesktopSelected', '0');
end;

function AutoUpdatesDefault: Boolean;
begin
  Result := PreviousAutoUpdatesEnabled;
end;

function AutoUpdatesOptedOut: Boolean;
begin
  Result := not AutoUpdatesDefault;
end;

function HasUpdatePreference: Boolean;
begin
  Result := PreviousHasUpdatePreference;
end;

{ Setup's default x86 process uses 32-bit pointers, including in 64-bit install mode. }
function EnvironmentBlock: LongWord;
  external 'GetEnvironmentStringsW@kernel32.dll stdcall';
function FreeEnvironmentBlock(Block: LongWord): Boolean;
  external 'FreeEnvironmentStringsW@kernel32.dll stdcall';
function EnvironmentLength(Value: LongWord): Integer;
  external 'lstrlenW@kernel32.dll stdcall';
function EnvironmentCopy(Dest: String; Source: LongWord; Count: Integer): LongWord;
  external 'lstrcpynW@kernel32.dll stdcall';
function SetEnvironment(Name, Value: String): Boolean;
  external 'SetEnvironmentVariableW@kernel32.dll stdcall';
function DeleteEnvironment(Name: String; Value: LongWord): Boolean;
  external 'SetEnvironmentVariableW@kernel32.dll stdcall';

procedure PutEnvironment(Name, Value: String);
begin
  if not SetEnvironment(Name, Value) then RaiseException('Cannot set maintenance environment.');
end;

procedure CleanEnvironment(Saved: TStringList);
var Block, Entry: LongWord; N, Split: Integer; Value: String;
begin
  Block := EnvironmentBlock;
  if Block = 0 then RaiseException('Cannot read maintenance environment.');
  try
    Entry := Block;
    N := EnvironmentLength(Entry);
    while N > 0 do begin
      SetLength(Value, N + 1);
      EnvironmentCopy(Value, Entry, N + 1);
      SetLength(Value, N);
      Split := Pos('=', Value);
      if Split > 1 then begin
        Saved.Add(Value);
        if not DeleteEnvironment(Copy(Value, 1, Split - 1), 0) then
          RaiseException('Cannot clear maintenance environment.');
      end;
      Entry := Entry + (N + 1) * 2;
      N := EnvironmentLength(Entry);
    end;
  finally
    FreeEnvironmentBlock(Block);
  end;
  { An allowlist also removes CLR profiler/startup-hook and module-path injection. }
  PutEnvironment('SystemRoot', ExpandConstant('{win}'));
  PutEnvironment('windir', ExpandConstant('{win}'));
  PutEnvironment('SystemDrive', ExtractFileDrive(ExpandConstant('{win}')));
  PutEnvironment('PATH', ExpandConstant('{sys}'));
  PutEnvironment('ComSpec', ExpandConstant('{sys}\cmd.exe'));
  PutEnvironment('PATHEXT', '.COM;.EXE;.BAT;.CMD');
  PutEnvironment('TEMP', ExpandConstant('{tmp}'));
  PutEnvironment('TMP', ExpandConstant('{tmp}'));
  PutEnvironment('PSModulePath', ExpandConstant('{sys}\WindowsPowerShell\v1.0\Modules'));
end;

procedure RestoreEnvironment(Saved: TStringList);
var I, Split: Integer; Value: String;
begin
  DeleteEnvironment('SystemRoot', 0);
  DeleteEnvironment('windir', 0);
  DeleteEnvironment('SystemDrive', 0);
  DeleteEnvironment('PATH', 0);
  DeleteEnvironment('ComSpec', 0);
  DeleteEnvironment('PATHEXT', 0);
  DeleteEnvironment('TEMP', 0);
  DeleteEnvironment('TMP', 0);
  DeleteEnvironment('PSModulePath', 0);
  for I := 0 to Saved.Count - 1 do begin
    Value := Saved[I];
    Split := Pos('=', Value);
    SetEnvironment(Copy(Value, 1, Split - 1), Copy(Value, Split + 1, Length(Value)));
  end;
end;

{ Politely ask a running tray agent (this session) to exit; never kill it. }
procedure CloseTray;
var Window: HWND; Tries: Integer;
begin
  Tries := 0;
  Window := FindWindowByClassName('SecblitzTrayWindow');
  while (Window <> 0) and (Tries < 20) do begin
    PostMessage(Window, 16, 0, 0); { WM_CLOSE }
    Sleep(250);
    Tries := Tries + 1;
    Window := FindWindowByClassName('SecblitzTrayWindow');
  end;
end;

function Maintain(Action: String): Boolean;
var Code: Integer; Saved: TStringList; Script, Arguments: String;
begin
  Script := ExpandConstant('{tmp}\secblitz-maintenance.ps1');
  if not SaveStringToFile(Script, UTF8Encode(MaintenanceSource), False) then
    RaiseException('Cannot extract maintenance script.');
  Saved := TStringList.Create;
  Code := -1;
  try
    CleanEnvironment(Saved);
    Arguments := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
      Script + '" -Action ' + Action;
    if IsUninstaller and ((Action = 'RemoveMonitor') or (Action = 'RemoveFilter') or (Action = 'Purge')) then
      Arguments := Arguments + ' -UninstallerDataPath "' +
        ChangeFileExt(ExpandConstant('{uninstallexe}'), '.dat') + '"';
    Result := Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
      Arguments, ExpandConstant('{sys}'), SW_HIDE, ewWaitUntilTerminated, Code);
  finally
    RestoreEnvironment(Saved);
    Saved.Free;
    DeleteFile(Script);
  end;
  { Prepare stopped what was running: 10 the monitor, 11 web protection, 12 both. }
  if Result and (Action = 'Prepare') and (Code >= 10) and (Code <= 12) then begin
    if (Code = 10) or (Code = 12) then ResumeAfterUpgrade := True;
    if (Code = 11) or (Code = 12) then ResumeFilterAfterUpgrade := True;
    Code := 0;
  end;
  if Result then Result := Code = 0;
  if not Result then Log('Secblitz maintenance failed: ' + Action + ', code ' + IntToStr(Code));
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  CloseTray;
  { Reject /DIR overrides too, not just directory-page edits. }
  if CompareText(ExpandConstant('{app}'), ExpandConstant('{autopf64}\Secblitz')) <> 0 then
  begin
    Result := ExpandConstant('{cm:FixedFolder}');
    Exit;
  end;
  if not Maintain('Prepare') then
    Result := ExpandConstant('{cm:Failed}');
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    { Inno may display an event exception yet finish with exit 0. Keep failure
      latched across every exception/early return until ALL requested work succeeds. }
    PostInstallFailed := True;
    if not Maintain('Secure') then
      RaiseException(ExpandConstant('{cm:Failed}'));
    { Web protection is registered turned off; it starts only when the person
      switches something on. An upgrade starts it again if it was running. }
    if not Maintain('InstallFilter') then
      RaiseException(ExpandConstant('{cm:Failed}'));
    if WizardIsTaskSelected('monitor') then
      if not Maintain('InstallMonitor') then
        RaiseException(ExpandConstant('{cm:Failed}'));
    if ResumeAfterUpgrade then begin
      if not Maintain('ResumeMonitor') then RaiseException(ExpandConstant('{cm:Failed}'));
      ResumeAfterUpgrade := False;
    end;
    if ResumeFilterAfterUpgrade then begin
      if not Maintain('ResumeFilter') then RaiseException(ExpandConstant('{cm:Failed}'));
      ResumeFilterAfterUpgrade := False;
    end;
    { The marker is a preference-preservation hint, not caller authentication.
      Setup already requires elevation; it grants no additional authority. }
    if ExpandConstant('{param:SECBLITZUPDATE|0}') = '1' then begin
      if not Maintain('PreserveUpdates') then RaiseException(ExpandConstant('{cm:Failed}'));
    end else if WizardIsTaskSelected('autoupdates') then begin
      if not Maintain('EnableUpdates') then RaiseException(ExpandConstant('{cm:Failed}'));
    end else if WizardSilent and HasUpdatePreference then begin
      { Older verified workers use /TASKS="" without the marker. Only an explicit
        interactive opt-out removes an existing enabled task on upgrade. }
      if not Maintain('PreserveUpdates') then RaiseException(ExpandConstant('{cm:Failed}'));
    end else begin
      if not Maintain('DisableUpdates') then RaiseException(ExpandConstant('{cm:Failed}'));
    end;
    PostInstallFailed := False;
  end;
end;

function GetCustomSetupExitCode: Integer;
begin
  Result := 0;
  if PostInstallFailed then Result := 20;
end;

function CanLaunchSecblitz: Boolean;
begin
  Result := not PostInstallFailed;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  { The error has already been shown; do not follow it with a success page. }
  Result := (PageID = wpFinished) and PostInstallFailed;
end;

procedure DeinitializeSetup;
begin
  { Also restore a formerly running monitor after cancellation/rollback. }
  if ResumeAfterUpgrade then
    if not Maintain('ResumeMonitor') then Log('Could not resume monitor after failed upgrade.');
  if ResumeFilterAfterUpgrade then
    if not Maintain('ResumeFilter') then Log('Could not resume web protection after failed upgrade.');
end;

{ ---- Removing Secblitz ----------------------------------------------------------
  Interactive uninstall asks one question, right after Windows' own "Are you
  sure" box: keep the PC as it is, or put everything back. A silent uninstall,
  and one the app started after it already put things back (/SECBLITZDONE),
  keeps the changes and never asks. }

function SecblitzExe: String;
begin
  Result := ExpandConstant('{app}\secblitz.exe');
end;

function HasSwitch(Switch: String): Boolean;
var I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), Switch) = 0 then Result := True;
end;

procedure AddLine(var Lines: TArrayOfString; Line: String);
var N: Integer;
begin
  Line := Trim(Line);
  if Line = '' then Exit;
  N := GetArrayLength(Lines);
  SetArrayLength(Lines, N + 1);
  Lines[N] := Line;
end;

procedure AddLines(var Lines: TArrayOfString; Text: String);
var I: Integer; Line: String;
begin
  Line := '';
  for I := 1 to Length(Text) do begin
    if Text[I] = #10 then begin
      AddLine(Lines, Line);
      Line := '';
    end else
      Line := Line + Text[I];
  end;
  AddLine(Lines, Line);
end;

function AddText(Form: TSetupForm; Top, Indent: Integer; Text: String; Bold: Boolean): TNewStaticText;
begin
  Result := TNewStaticText.Create(Form);
  Result.Parent := Form;
  Result.Left := ScaleX(16) + Indent;
  Result.Top := Top;
  Result.Width := Form.ClientWidth - ScaleX(32) - Indent;
  Result.WordWrap := True;
  Result.Caption := Text;
  if Bold then Result.Font.Style := [fsBold];
  Result.AutoSize := True;
end;

function AddChoice(Form: TSetupForm; Top: Integer; Text: String): TNewRadioButton;
begin
  Result := TNewRadioButton.Create(Form);
  Result.Parent := Form;
  Result.Left := ScaleX(16);
  Result.Top := Top;
  Result.Width := Form.ClientWidth - ScaleX(32);
  Result.Height := ScaleY(20);
  Result.Caption := Text;
end;

{ A web protection switch is on. Only true/false values hold "true". }
function WebProtectionOn: Boolean;
var
  Config: AnsiString;
begin
  Result := LoadStringFromFile(ExpandConstant('{commonappdata}\Secblitz\Filter\config.json'), Config)
    and (Pos('true', String(Config)) > 0);
end;

{ The one question. False means Cancel: nothing has been touched yet. }
function AskRemoveChoice(var PutBack: Boolean): Boolean;
var
  Form: TSetupForm;
  Question, KeepDetail, PutDetail, Note, WebNote: TNewStaticText;
  KeepChoice, PutChoice: TNewRadioButton;
  RemoveButton, CancelButton: TNewButton;
  Top: Integer;
begin
  { Inno 6.3+: client size, then whether to keep it when the dialog font scales. }
  Form := CreateCustomForm(ScaleX(470), ScaleY(300), False, False);
  try
    { The form can scale its starting size a second time on a high-DPI screen. }
    Form.ClientWidth := ScaleX(470);
    Form.Caption := CustomMessage('RemoveTitle');
    Top := AddBanner(Form, ExpandConstant('{app}\art'), Form.ClientWidth) + ScaleY(16);
    Question :=AddText(Form, Top, 0, CustomMessage('RemoveQuestion'), True);
    Top := Question.Top + Question.Height + ScaleY(14);
    KeepChoice := AddChoice(Form, Top, CustomMessage('KeepChoice'));
    Top := KeepChoice.Top + KeepChoice.Height + ScaleY(2);
    KeepDetail := AddText(Form, Top, ScaleX(20), CustomMessage('KeepDetail'), False);
    Top := KeepDetail.Top + KeepDetail.Height + ScaleY(12);
    PutChoice := AddChoice(Form, Top, CustomMessage('PutBackChoice'));
    Top := PutChoice.Top + PutChoice.Height + ScaleY(2);
    PutDetail := AddText(Form, Top, ScaleX(20), CustomMessage('PutBackDetail'), False);
    Top := PutDetail.Top + PutDetail.Height + ScaleY(16);
    Note := AddText(Form, Top, 0, CustomMessage('RemoveNote'), False);
    Top := Note.Top + Note.Height + ScaleY(18);
    if WebProtectionOn then begin
      WebNote := AddText(Form, Top - ScaleY(12), 0, CustomMessage('WebStops'), False);
      Top := WebNote.Top + WebNote.Height + ScaleY(18);
    end;

    CancelButton := TNewButton.Create(Form);
    CancelButton.Parent := Form;
    CancelButton.Width := ScaleX(90);
    CancelButton.Height := ScaleY(23);
    CancelButton.Left := Form.ClientWidth - ScaleX(16) - CancelButton.Width;
    CancelButton.Top := Top;
    CancelButton.Caption := SetupMessage(msgButtonCancel);
    CancelButton.ModalResult := mrCancel;
    CancelButton.Cancel := True;

    RemoveButton := TNewButton.Create(Form);
    RemoveButton.Parent := Form;
    RemoveButton.Width := ScaleX(130);
    RemoveButton.Height := ScaleY(23);
    RemoveButton.Left := CancelButton.Left - ScaleX(8) - RemoveButton.Width;
    RemoveButton.Top := Top;
    RemoveButton.Caption := CustomMessage('RemoveTitle');
    RemoveButton.ModalResult := mrOk;
    RemoveButton.Default := True;

    Form.ClientHeight := Top + RemoveButton.Height + ScaleY(16);
    KeepChoice.Checked := True;
    Form.ActiveControl := KeepChoice;
    Result := Form.ShowModal = mrOk;
    PutBack := Result and PutChoice.Checked;
  finally
    Form.Free;
  end;
end;

{ Personal settings first, then the machine part. The uninstaller cannot run
  anything as the original person (Inno allows that only in Setup), so the
  personal part runs elevated, which is the same person's account and settings
  when they approved the prompt themselves. The machine part writes one plain line per
  thing it left to a file in the uninstaller's private temp folder; the lines
  are UTF-8. Failures never stop the removal: the person already chose it. }
procedure PutEverythingBack;
var
  Lines: TArrayOfString;
  Raw: AnsiString;
  Output, Report: String;
  Code, I, Shown: Integer;
  PersonalLeft: Boolean;
begin
  UninstallProgressForm.StatusLabel.Caption := CustomMessage('PuttingBack');
  { Bringing apps back can take a minute; a moving bar shows it is working. }
  UninstallProgressForm.ProgressBar.Style := npbstMarquee;
  SetArrayLength(Lines, 0);

  PersonalLeft := True;
  if Exec(SecblitzExe, 'uninstall-revert --user', ExpandConstant('{app}'),
      SW_HIDE, ewWaitUntilTerminated, Code) then
    PersonalLeft := Code <> 0;
  Log('Secblitz put back (personal): left=' + IntToStr(Code));
  if PersonalLeft then AddLine(Lines, CustomMessage('PersonalLeft'));

  Output := ExpandConstant('{tmp}\secblitz-put-back.txt');
  DeleteFile(Output);
  if Exec(ExpandConstant('{sys}\cmd.exe'),
      '/D /S /C ""' + SecblitzExe + '" uninstall-revert > "' + Output + '" 2>NUL"',
      ExpandConstant('{sys}'), SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0) then begin
    if LoadStringFromFile(Output, Raw) then AddLines(Lines, UTF8Decode(Raw));
  end else begin
    Log('Secblitz put back (machine) failed, code ' + IntToStr(Code));
    AddLine(Lines, CustomMessage('SettingsLeft'));
  end;
  DeleteFile(Output);
  UninstallProgressForm.ProgressBar.Style := npbstNormal;

  if GetArrayLength(Lines) = 0 then Exit;
  Report := CustomMessage('LeftIntro');
  Shown := GetArrayLength(Lines);
  if Shown > 12 then Shown := 12;
  for I := 0 to Shown - 1 do
    Report := Report + #13#10 + '- ' + Lines[I];
  if not UninstallSilent then
    SuppressibleMsgBox(Report, mbInformation, MB_OK, IDOK);
end;

{ Both choices: the current person's own Secblitz folder goes too. }
procedure CleanUserData;
var Code: Integer;
begin
  if not Exec(SecblitzExe, 'uninstall-cleanup --user', ExpandConstant('{app}'),
      SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
    Log('Secblitz could not remove the per-user data folder, code ' + IntToStr(Code));
end;

{ Runs after Windows' "Are you sure" box and before anything is removed.
  Abort here ends the uninstall quietly with everything still in place. }
procedure PrepareRemoval;
var Ready: Boolean;
begin
  UninstallPutBack := False;
  if HasSwitch('/SECBLITZDONE') then
    Log('Secblitz uninstall: the app already answered the question; keeping the PC as it is.')
  else if UninstallSilent then
    Log('Secblitz uninstall: a silent uninstall keeps the changes.')
  else if not AskRemoveChoice(UninstallPutBack) then begin
    Log('Secblitz uninstall: cancelled before anything was touched.');
    Abort;
  end;
  CloseTray;
  try
    Ready := Maintain('RemoveMonitor');
  except
    Log('Secblitz uninstall maintenance exception: ' + GetExceptionMessage);
    Ready := False;
  end;
  if not Ready then begin
    Log(ExpandConstant('{cm:RemoveFailed}'));
    if not UninstallSilent then
      SuppressibleMsgBox(ExpandConstant('{cm:RemoveFailed}'), mbError, MB_OK, IDOK);
    Abort;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usAppMutexCheck then
    PrepareRemoval
  else if CurUninstallStep = usUninstall then begin
    { The program is still in place here. Each part is tried on its own; a
      failure is logged and the removal carries on. }
    if UninstallPutBack then
      try
        PutEverythingBack;
      except
        Log('Secblitz put back exception: ' + GetExceptionMessage);
      end;
    try
      if not Maintain('RemoveFilter') then
        Log('Secblitz could not fully turn off web protection.');
    except
      Log('Secblitz web protection removal exception: ' + GetExceptionMessage);
    end;
    try
      CleanUserData;
    except
      Log('Secblitz per-user cleanup exception: ' + GetExceptionMessage);
    end;
  end else if CurUninstallStep = usPostUninstall then begin
    try
      if not Maintain('Purge') then
        Log('Secblitz could not remove all of its data.');
    except
      Log('Secblitz uninstall data cleanup exception: ' + GetExceptionMessage);
    end;
    // Setup's own retry can run while unins000.exe is still being deleted;
    // by now it is gone, so the empty program folder can go too.
    if DirExists(ExpandConstant('{app}')) and not RemoveDir(ExpandConstant('{app}')) then
      Log('Secblitz program folder is not empty; leaving it.');
  end;
end;
