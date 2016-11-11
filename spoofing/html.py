def createHistory():
    history = open('historico.html', 'w')
    history.truncate()
    history.write("<html>\n")
    history.write("<header>\n")
    history.write("<title>Historico de Navegacao</title>\n")
    history.write("</header>\n")
    history.write("<body>\n")
    history.write("<ul>\n")
    history.write("</ul>\n")
    history.write("</body>\n")
    history.write("</html>\n")
    history.close()

def addListEntry(time, ip, host_name, link):
    try:
        with open("historico.html", "r+") as history:
            for line in history:
                if line == "</ul>\n":
                    entry = '<li>' + time.strftime('%d %m %Y %I:%M:%S') + ' - ' + ip + ' (' + host_name + ') - <a href="http://' + link + '">' + link + '</a></li>'
                    history.write(entry)
                    history.write("</ul>\n")
                    history.write("</body>\n")
                    history.write("</html>\n")
                    history.close()
                    break
    except Exception as e:
        print (e)