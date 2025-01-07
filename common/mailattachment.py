import smtplib
from os.path import basename
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate


def send_mail(send_from: str, 
              send_to: list[str], 
              subject: str, 
              text: str, 
              files: list[str] = None,
              server: str = None, 
              port: int = None,
              use_tls: bool = True, 
              username: str = None, 
              password: str = None):
    
    ''' Send an email using an SMTP server. Authentication is optional. 
    
    Please note that google relies on authentication and uses port 587 for SMTP.
    Function takes a list of email destinations as well as a list of files.
    
    At a minimum, the only things that do not have to be set to use the function are "subject", "text" and "files", when using google smtp.

    Function was originally written to handle multiple files, i.e a list of strings (filenames), this functionality is not used by the netssh.py at the moment
    
    '''


    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = COMMASPACE.join(send_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject
    msg.attach(MIMEText(text))

    
    try:
        for file in files or []:
            with open(file, "rb") as current:
                part = MIMEApplication(
                    current.read(),
                    Name=basename(file)
                )
            # After the file is closed
            part['Content-Disposition'] = 'attachment; filename="%s"' % basename(file)
            msg.attach(part)

        with smtplib.SMTP(server, port) as smtp:
        # Check if username is set, enables TLS if username is detected
            if use_tls:
                smtp.starttls()
            if username:
                smtp.login(username, password)
            smtp.sendmail(send_from, send_to, msg.as_string())
    
    except IOError as e:
        print("\n\nEmail not sent,", f"Error message: {e}")
    except smtplib.SMTPRecipientsRefused as e:
        print("\n\nEmail not sent,", f"Error message: {type(e)}")
    except Exception as e:
        print("\n\nEmail not sent,", f"Error message: {e}")
    else:
        print("\n\nEmail sent")