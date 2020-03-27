def createHistory():
    history = open('historico.html', 'w')
    history.truncate()
    history.write("<header>\n")
    history.write("<title>Historico de Navegacao</title>\n")
    history.write("</header>\n")

    history.write("commit test\n")
    history.close()

def addListEntry(time, ip, host_name, link):
    try:
        with open("historico.html", "a") as history:
            entry = '<li>' + time.strftime('%d %m %Y %I:%M:%S') + ' - ' + ip + ' (' + host_name + ') - <span>' + link + '</span>\n'
            history.write(entry)

    except Exception as e:
        print (e)
