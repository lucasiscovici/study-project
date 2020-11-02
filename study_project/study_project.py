# mypy: ignore-errors
import os
import sys
import tempfile

import dvc.api
import git
from dvc import main


class Utils:
    class RE:
        @staticmethod
        def captureValueInLine(text, pattern, sep=":"):
            import re

            return re.findall(
                f"^.*{pattern}{sep}(.+)$", text, flags=re.MULTILINE
            )[0].strip()

        @staticmethod
        def match(text, pattern):
            import re

            return re.match(pattern, text) is not None

    class Hash:
        @staticmethod
        def md5(string):
            import hashlib

            return hashlib.md5(string.encode()).hexdigest()  # nosec

        @staticmethod
        def function_md5(func):
            import inspect

            return Utils.Hash.md5(inspect.getsource(func))

    class Df:
        @staticmethod
        def to_csv(df, filename, index=True):
            df.to_csv(filename, index=False)

        @staticmethod
        def to_csv_string(df, index=True):
            import io

            s = io.StringIO()
            Utils.Df.to_csv(df, s, index=index)
            return s.getvalue()

        @staticmethod
        def from_csv_string(csvString):
            import io

            import pandas as pd

            s = io.StringIO(csvString)
            return pd.read_csv(s)

    class String:
        @staticmethod
        def remove_accents(text):
            import unicodedata

            return "".join(
                c
                for c in unicodedata.normalize("NFD", text)
                if unicodedata.category(c) != "Mn"
            )

        @staticmethod
        def remove_not_alphanumeric(text):
            import re

            return re.sub("[^a-zA-Z0-9 ]", "", text)

        @staticmethod
        def parse(text, sep=":"):
            import re

            dico = {}
            if len(text) == 0:
                return dico
            for i in text.split("\n"):
                m = re.findall(f"^([^{sep}]+){sep}(.+)$", i)
                dico[m[0][0].strip()] = m[0][1].strip()
            return dico

    class Shell:
        @staticmethod
        def command(commandString, shell=False):
            import shlex
            import subprocess

            process = subprocess.Popen(
                shlex.split(commandString) if not shell else commandString,
                stdout=subprocess.PIPE,
                shell=shell,  # nosec
            )
            output, error = process.communicate()
            return Struct(
                **{
                    "output": output.decode("utf-8"),
                    "error": output.decode("utf-8")
                    if (output and "error" in output.decode("utf-8").lower())
                    else error,
                    "commandString": commandString,
                }
            )

    class File:
        @staticmethod
        def exist(file):
            import os.path

            return os.path.isfile(file)

        @staticmethod
        def read(filename):
            with open(filename) as f:
                output = f.read()
            return output

        @staticmethod
        def write(text, filename):
            with open(filename, "w") as f:
                f.write(text)

        @staticmethod
        def tmp(ext="csv"):
            file = TMP_FILE()
            return file.get_filename(ext)

        @staticmethod
        def tmp_delete(filename):
            file = TMP_FILE()
            file.filename = filename
            file.delete()

        @staticmethod
        def touch(file):
            Utils.Shell.command(f"touch '{file}'")

    class Dir:
        @staticmethod
        def mk(dir, p=None):
            os.mkdir(dir)

        @staticmethod
        def exist(dir):
            return os.path.isdir(dir)

    @staticmethod
    def ifelse(condition, true, false=""):
        return true if condition else false

    @staticmethod
    def md5FromDf(df, index=False):
        md5 = Utils.Hash.md5(Utils.Df.to_csv_string(df, index=index))
        return md5


class TMP_FILE:
    def __init__(self):
        self.filename = None

    def get_filename(self, ext="png"):
        if self.filename is not None:
            self.delete()
        _, self.filename = tempfile.mkstemp(suffix="." + ext)
        return self.filename

    def delete(self):
        # print(self.i)
        os.remove(self.filename)


class Struct:
    def __init__(self, **entries):
        self.__dict__.update(entries)

    def __str__(self):
        a = ""
        for i in self.__dict__.keys():
            a += f"{i} :"
            a += f"\n\t{self.__dict__[i]}\n"
        return a


class Git:
    installed = False

    @staticmethod
    def check_installed():
        return Git.installed or os.path.isdir(os.getcwd() + "/.git")

    @staticmethod
    def install(add=True, commit=True, message="git installed"):
        print("\tset up Git...")
        g = git.cmd.Git(os.getcwd())
        g.init()
        Utils.Shell.command("touch .gitignore")
        if add:
            Git.add([".gitignore"])
        if commit:
            StudyProjectEnv.commit(message)
        print("\tGit initialized")
        Git.installed = True

    @staticmethod
    def addTag(name, desc):
        g = git.cmd.Git(os.getcwd())
        g.tag(["-a", f"'{name}'", "-m", f"'{desc}'"])

    @staticmethod
    def getBranch():
        rep = Utils.Shell.command(f"git branch --show-current")
        if rep.error:
            raise Exception(rep)
        return rep.output.strip()

    @staticmethod
    def deleteBranch(name, force=False):
        Utils.Shell.command(
            f"git branch {Utils.ifelse(force,'-D','-d')} {name}"
        )

    @staticmethod
    def checkBranch(name):
        rep = Utils.Shell.command(
            f"git branch  --list '{name}' | tr -d ' '", shell=True  # nosec
        )
        if rep.error:
            raise Exception(rep)
        branch = rep.output
        return len(branch) > 0

    @staticmethod
    def addBranch(name, checkout=True):
        if Git.checkBranch(name):
            return
        if checkout:
            g = git.cmd.Git(os.getcwd())
            g.checkout(["-b", f"{name}"])
        else:
            g = git.cmd.Git(os.getcwd())
            g.branch([f"{name}"])

    @staticmethod
    def getNoHooks():
        return "-c core.hooksPath=/dev/null"

    @staticmethod
    def goToBranch(name, no_hooks=False):
        # g = git.cmd.Git(os.getcwd())
        # g.checkout([f"{name}"])
        hooks = Git.getNoHooks() if no_hooks else ""
        Utils.Shell.command(f"git {hooks} checkout {name}")

    @staticmethod
    def toBrancheName(name, sep="-"):
        import re

        name = name.strip()
        name = Utils.String.remove_accents(name)
        name = Utils.String.remove_not_alphanumeric(name)
        name = re.sub(" +", " ", name)
        name = re.sub(" ", sep, name)
        name = name.lower()
        return name

    @staticmethod
    def getConfigUser(author):
        return " ".join(
            [
                "-c",
                f"user.name='{author.split('<')[0].strip()}'",
                "-c",
                f"user.email='{author.split('<')[1][:-1].strip()}'",
            ]
        )

    @staticmethod
    def commit(message, author=""):
        if len(author) > 0:
            commiter = Git.getConfigUser(author)
            author = f'--author="{author}"'
            message = message.replace("'", '"')
            rep = Utils.Shell.command(
                f"git {commiter} commit {author} -m '{message}'"
            )
            if rep.error:
                raise Exception(rep.error)
            # if rep.output:
            #   print(rep.output,rep.commandString)
            return
        g = git.cmd.Git(os.getcwd())
        g.commit([author, "-m", f"'{message}'"])

    @staticmethod
    def merge(branch, no_ff=True, message="", author=""):
        if len(author) > 0:
            commiter = Git.getConfigUser(author)
            message = message.replace("'", '"')
            messageN = f"-m '{message}'"
            rep = Utils.Shell.command(
                f"git {commiter} merge {Utils.ifelse(no_ff,'--no-ff')} {Utils.ifelse(message,messageN)} {branch}"
            )
            if rep.error:
                print(rep)
                raise Exception(rep.error)
            # if rep.output:
            #   print(rep.output, rep.commandString)
            return
        g = git.cmd.Git(os.getcwd())
        g.merge([Utils.ifelse(no_ff, "--no-ff"), branch])

    @staticmethod
    def add(listToAdd):
        g = git.cmd.Git(os.getcwd())
        g.add([] + listToAdd)

    @staticmethod
    def checkIdentity():
        rep = Git.config("user.name", globally=True)
        if rep.error:
            raise Exception(rep.error)
        rep2 = Git.config("user.name", globally=False)
        if rep2.error:
            raise Exception(rep2.error)
        return len(rep.output) > 0 or len(rep2.output) > 0

    @staticmethod
    def config(k, v=None, globally=False, remove=False):
        return Utils.Shell.command(
            f"git config {Utils.ifelse(globally,'--global')} {Utils.ifelse(v is None and not remove,'--get')} {Utils.ifelse(remove,'--unset')} {k} {Utils.ifelse(v is not None, v)}"
        )


class Dvc:
    installed = False
    author = "DvcBot <DvcBot@DvcBot.DvcBot>"

    @staticmethod
    def check_installed():
        return Dvc.installed or os.path.isdir(os.getcwd() + "/.dvc")

    @staticmethod
    def install():
        print("\tset up dvc...")
        k = main.main(["init", "--quiet"])
        Dvc.config("core.autostage", "true")
        Git.add([".dvc/config"])
        main.main(["install"])
        StudyProjectEnv.commit("dvc installed (config+hooks)")
        print("\tDvc initialized")
        Dvc.installed = True

    @staticmethod
    def commit(message, author=None):
        author = Dvc.author if author is None else author
        return Git.commit(message, author=Dvc.author)

    @staticmethod
    def merge(branch, no_ff=True, message="", author=None):
        author = Dvc.author if author is None else author
        return Git.merge(branch, no_ff=no_ff, author=author, message=message)

    @staticmethod
    def config(k, v):
        main.main(["config", k, v])

    @staticmethod
    def addDataFromDF(df, name, path="", to="csv", ext="csv", index=False):
        file = TMP_FILE()
        if to not in ["csv"]:
            print(f"to:'{to}' not implemented")
            return
        df.to_csv(file.get_filename("csv"), index=index)
        if len(path) > 0:
            path = path + "/"
        main.main(
            [
                "add",
                "--external",
                "--file",
                f"{path}{name}.{ext}.dvc",
                file.filename,
            ]
        )

    @staticmethod
    def getMd5(filename, path="", ext="csv"):
        if len(path) > 0:
            path = path + "/"
        if not Utils.File.exist(f"{path}{filename}.{ext}.dvc"):
            return None
        file = Utils.File.read(f"{path}{filename}.{ext}.dvc")
        return Utils.RE.captureValueInLine(file, "md5")

    @staticmethod
    def open(fileName):
        with dvc.api.open(fileName) as fd:
            text = fd.read()
        return text

    @staticmethod
    def read(fileName):
        return dvc.api.read(fileName)


class StudyProjectEnv:
    installed = False
    path = ".study_project"
    step = 0
    prefixe = "study_project : "
    default_branch = "study_project_set_up"
    data_path = "data"
    project_prefixe = "project"

    @staticmethod
    def add():
        Git.add([StudyProjectEnv.path + "/"])

    @staticmethod
    def check_installed():
        return StudyProjectEnv.installed or os.path.isdir(
            os.getcwd() + "/" + StudyProjectEnv.path
        )

    @staticmethod
    def install():
        print("\tset up study_project...")
        os.mkdir(StudyProjectEnv.path)
        os.mkdir(StudyProjectEnv.data_path)
        Utils.File.touch(StudyProjectEnv.data_path + "/.gitignore")
        os.mkdir(StudyProjectEnv.path + "/projects")
        Utils.File.touch(StudyProjectEnv.path + "/projects" + "/.gitignore")
        os.mkdir(StudyProjectEnv.path + "/studies")
        Utils.File.touch(StudyProjectEnv.path + "/studies" + "/.gitignore")
        os.mkdir(StudyProjectEnv.path + "/data")
        Utils.File.touch(StudyProjectEnv.path + "/data" + "/.gitignore")
        Utils.Shell.command(f"touch {StudyProjectEnv.path}/.gitignore")
        print("\tstudy_project initialized")
        StudyProjectEnv.installed = True
        Git.add(
            [
                StudyProjectEnv.path,
                StudyProjectEnv.path + "/",
                StudyProjectEnv.data_path,
                StudyProjectEnv.data_path + "/",
            ]
        )
        StudyProjectEnv.commit("study_project installed")

    @staticmethod
    def addBranch(name):
        brName = f"{StudyProjectEnv.step}-{name}"
        Git.addBranch(brName)
        StudyProjectEnv.step += 1
        return brName

    @staticmethod
    def getVersions(id):
        projPath = StudyProjectEnv.getProjPath(id)
        if not Utils.File.exist(projPath + "/versions"):
            return ""
        versions = Utils.File.read(projPath + "/versions")
        return versions

    @staticmethod
    def getVersion(id, hash):
        versionsDict = StudyProjectEnv.getVersionsDict(id)
        return versionsDict[hash]

    @staticmethod
    def saveVersions(id, versions):
        projPath = StudyProjectEnv.getProjPath(id)
        Utils.File.write(versions, filename=projPath + "/versions")
        return versions

    @staticmethod
    def getVersionsDict(id):
        versions = Utils.String.parse(StudyProjectEnv.getVersions(id))
        return versions

    @staticmethod
    def getVersionNumber(id):
        brName = Git.toBrancheName(id)
        versions = StudyProjectEnv.getVersionsDict(id)
        return len(versions)

    @staticmethod
    def addVersion(v, hash, id):
        versions = StudyProjectEnv.getVersions(id)
        StudyProjectEnv.saveVersions(
            id, f"{versions}\n{hash}: {v}\n{v}: {hash}"
        )

    @staticmethod
    def addProjectBranch(id):
        nb = StudyProjectEnv.getVersionNumber(id)
        brName = (
            f"{StudyProjectEnv.project_prefixe}-{Git.toBrancheName(id)}-v{nb}"
        )
        Git.addBranch(brName)
        return (brName, nb)

    @staticmethod
    def check_all_installed():
        install = False
        if (
            not Git.check_installed()
            or not Dvc.check_installed()
            or not StudyProjectEnv.check_installed()
        ):
            if (
                Git.check_installed()
                or Dvc.check_installed()
                or StudyProjectEnv.check_installed()
            ):
                print(
                    "study_project : git/Dvc/study_project are already installed, we can't for the moment install only on off them"
                )
                return False
            install = True
            print("Set Up Study Project ....")
            if not Git.check_installed():
                # StudyProjectEnv.check_init()
                Git.install()
                StudyProjectEnv.addBranch(f"set-up")
                # Git.checkout("master")
                # Git.merge("install-git")
            if not Dvc.check_installed():
                # StudyProjectEnv.addBranch(f"install-dvc")
                Dvc.install()
            if not StudyProjectEnv.check_installed():
                # StudyProjectEnv.addBranch(f"install-study-project")
                StudyProjectEnv.install()
                currBranche = Git.getBranch()
                Git.goToBranch("master", no_hooks=True)
                StudyProjectEnv.merge(currBranche, message="set-up")
                Git.deleteBranch(currBranche)
            print("Study Project OK")
            return True
        return True

    @staticmethod
    def check_init():
        rep = Utils.Shell.command("git branch")
        if rep.error:
            raise Exception(rep.error)
        if len(rep.output) == 0:
            Utils.Shell.command("touch .initial_commit")
            Git.add([".initial_commit"])
            Git.commit()

    @staticmethod
    def goToBranch(name):
        Git.goToBranch(name)

    @staticmethod
    def commit(message, prefixe=None):
        prefixe = StudyProjectEnv.prefixe if prefixe is None else prefixe
        return Dvc.commit(f"{prefixe}{message}")

    @staticmethod
    def merge(*args, message="", prefixe=None, **xargs):
        prefixe = StudyProjectEnv.prefixe if prefixe is None else prefixe
        message = message if len(message) == 0 else f"{prefixe}{message}"
        return Dvc.merge(*args, message=message, **xargs)

    @staticmethod
    def addData(data, filename, path=None):
        path = StudyProjectEnv.data_path if path is None else path
        md5OfData = Utils.md5FromDf(data)
        md5InFileName = Dvc.getMd5(filename, path)
        if md5InFileName != md5OfData:
            Dvc.addDataFromDF(data, filename, path=path)
            return (True, md5OfData)
        return (False, md5OfData)

    @staticmethod
    def saveData(data, dataHash):
        projPath = StudyProjectEnv.path + "/data"
        if not Utils.File.exist(projPath + "/" + dataHash):
            StudyProjectEnv.addData(data.train, data.fileName + "_train")
            StudyProjectEnv.addData(data.test, data.fileName + "_test")
            fileStr = Data.get_file_export(
                data,
                lambda name, data_: StudyProjectEnv.addData(
                    data_, data.fileName + f"_data_{name}"
                ),
            )
            Utils.File.write(fileStr, projPath + "/" + dataHash)

    @staticmethod
    def getFileData(dataParsed, data_name, id):
        fileName = Git.toBrancheName(id, sep="_")
        path = f"{StudyProjectEnv.data_path}/{fileName}_{data_name}.csv"
        pathDvc = f"{path}.dvc"
        if Utils.File.exist(pathDvc):  # save fileName in data
            dataFile = Utils.File.read(pathDvc)
            md5File = Utils.RE.captureValueInLine(dataFile, "md5")
            pathFile = Utils.RE.captureValueInLine(dataFile, "path")
            if dataParsed[data_name] == md5File:
                fileData = Dvc.read(pathFile)
                return Utils.Df.from_csv_string(fileData)

    @staticmethod
    def getData(dataHash):
        projPath = StudyProjectEnv.path + "/data"
        if Utils.File.exist(projPath + "/" + dataHash):
            dataString = Utils.File.read(projPath + "/" + dataHash)
            dataParsed2 = Utils.String.parse(
                dataString, sep=":"
            )  # {i: Utils.String.parse(dataString,sep=":") for i in ["id","comment","train","test","target"]}
            data = {}
            dataParsed = {}
            for k, v in dataParsed2.items():
                if Utils.RE.match(k, "^data."):
                    data[k[len("data.") :]] = StudyProjectEnv.getFileData(
                        {"data_" + k[len("data.") :]: v},
                        "data_" + k[len("data.") :],
                        dataParsed["id"],
                    )
                else:
                    dataParsed[k] = v
            dataParsed["data"] = data
            dataFiles = {
                i: StudyProjectEnv.getFileData(dataParsed, i, dataParsed["id"])
                for i in ["train", "test"]
            }
            dataReady = {**dataParsed, **dataFiles}
            return Data().setData(**dataReady)
        print("error : {projPath + " / " + dataHash}")
        return Data()

    @staticmethod
    def forgotData(dataHash):
        pass

    @staticmethod
    def getProjPath(id):
        return (
            StudyProjectEnv.path + "/projects/" + Git.toBrancheName(id, sep="_")
        )

    @staticmethod
    def saveProject(project):
        def addCommit():
            StudyProjectEnv.add()
            StudyProjectEnv.commit(f"save Project '{project.id}'")

        def upVersion(dataHash, setUpMd5Proj):
            StudyProjectEnv.addVersion(
                project.v,
                Utils.Hash.md5(f"{dataHash}\n{setUpMd5Proj}"),
                project.id,
            )

        projPath = StudyProjectEnv.getProjPath(project.id)

        if not Utils.Dir.exist(projPath):
            Utils.Dir.mk(projPath)

        # os.mkdir(StudyProjectEnv.path+"/project/"+Git.toBrancheName(project.id,sep="_")+"/studies")
        # os.mkdir(StudyProjectEnv.path+"/project/"+Git.toBrancheName(project.id,sep="_")+"/data")

        dataHash = {data.get_hash(): data.id for data in project.data.values()}
        dataHash = dict(sorted(dataHash.items(), key=lambda a: a[0]))
        dataHashDico = dataHash

        dataHashStr = "\n".join(dataHash.keys())
        if not Utils.File.exist(f"{projPath}/data"):
            lastDataHashStr = ""
        else:
            lastDataHashStr = Utils.File.read(f"{projPath}/data")

        if lastDataHashStr != dataHashStr:
            Utils.File.write(dataHashStr, filename=f"{projPath}/data")
            lastDataHash = set(lastDataHashStr.split("\n"))
            dataHash = set(dataHash.keys())
            newData = dataHash - lastDataHash
            pastData = lastDataHash - dataHash
            for i in newData:
                StudyProjectEnv.saveData(project.data[dataHashDico[i]], i)
            for i in pastData:
                StudyProjectEnv.forgotData(i)

        setUpMd5Proj = Utils.Hash.function_md5(project.setUp)
        if Utils.File.exist(f"{projPath}/setUp"):
            setUpMd5 = Utils.File.read(f"{projPath}/setUp")
            if setUpMd5Proj == setUpMd5:
                upVersion(lastDataHashStr, setUpMd5Proj)
                return
        Utils.File.write(setUpMd5Proj, filename=f"{projPath}/setUp")

        upVersion(lastDataHashStr, setUpMd5Proj)

        addCommit()

        # studiesHash=[study.get_hash() for study in project.studies.values()]
        # Utils.File.write("\n".join(dataHash),filename=f"{projPath}/studies")

        # hash([project.data,project.studies])
        # StudyProjectEnv.create_project()

    @staticmethod
    def getProject(id, setUp):
        projPath = StudyProjectEnv.getProjPath(id)

        projStr = ""
        if Utils.Dir.exist(projPath):
            proj = StudyProject(id)

            if Utils.File.exist(f"{projPath}/setUp"):
                setUpMd5Proj = Utils.Hash.function_md5(setUp)
                setUpMd5 = Utils.File.read(f"{projPath}/setUp")
                if setUpMd5Proj == setUpMd5:
                    proj.setUp = setUp
                else:
                    proj.setUp = "outdated"
                    print("SetUp is not the saved")
                    return proj
                # projStr+="\n"+setUpMd5

            if Utils.File.exist(f"{projPath}/data"):
                DataHash = Utils.File.read(f"{projPath}/data")
                data = {
                    i.id: i
                    for i in [
                        StudyProjectEnv.getData(Datahashi)
                        for Datahashi in DataHash.split("\n")
                    ]
                }
                proj.data = data
            projHash = Utils.Hash.md5(f"{dataHash}\n{setUpMd5Proj}")
            proj.v = StudyProjectEnv.getVersion(projHash, proj.id)
            return proj
        return None


class Data:
    def setData(self, /, id, train, test, target, comment="", data={}):
        # check is pandas df, series
        self.id = id
        self.train = train
        self.test = test
        self.target = target
        self.comment = comment
        self.data = data

        # maybe -> StudyProjectEnv should do that
        brName = Git.toBrancheName(id)
        self.fileName = Git.toBrancheName(id, sep="_")
        fileName = self.fileName
        (new, md5_train) = StudyProjectEnv.addData(
            self.train, f"{fileName}_train"
        )
        # (new2, md5_target) = StudyProjectEnv.addData(
        #     self.target, f"{fileName}_target"
        # )
        (new2, md5_test) = StudyProjectEnv.addData(
            self.test, f"{fileName}_test"
        )
        new3 = False
        data_md5 = {}
        for k, v in self.data.items():
            (new_, md5_data_) = StudyProjectEnv.addData(
                v, f"{fileName}_data_{k}"
            )
            data_md5[k] = md5_data_
            new3 = new3 or new_
        self.data_md5 = data_md5
        self.md5_train = md5_train
        self.md5_test = md5_test
        if new or new2 or new3:
            StudyProjectEnv.commit(f"add Data '{id}'")
        # StudyProjectEnv.addBranch(f"add-data-{brName}")
        return self

    @staticmethod
    def get_file_export(data, data_data_cb=lambda name, data_: True):
        comment = data.comment.replace("\n", "\\n")
        fileStr = f"""id: {data.id}
comment: {comment}
target: {data.target}
train: {data.md5_train}
test: {data.md5_test}"""
        for name, data_ in data.data.items():
            data_data_cb(name, data_)
            fileStr += f"\ndata.{name}: {data.data_md5[name]}"
        return fileStr

    def get_hash(self):
        fileStr = Data.get_file_export(self)
        return Utils.Hash.md5(fileStr)


class Study:
    """docstring for Study"""

    def __init__(self, id, data=None):
        self.id = id
        self.data = data


class StudyProject:
    def __init__(self, id):
        self.data = {}
        self.studies = {}
        self.id = id

    def saveData(self, id, train, test, target, comment="", data={}):
        if id in self.data:
            print(f"\tData '{id}' : loaded ")
            return self.data[id]
        print(f"\tData '{id}' : creating... ")
        dataObj = Data()
        dataObj.setData(id, train, test, target, comment, data)
        self.data[id] = dataObj
        print(f"\tData '{id}' : ok ")
        StudyProjectEnv.saveProject(self)

    @classmethod
    def getOrCreate(self, id, setUp, recreate=False):
        if not StudyProjectEnv.check_all_installed():
            return

        def create_project():
            Git.goToBranch("master")
            (brName, v) = StudyProjectEnv.addProjectBranch(id)
            df = " " * len(f"Project '{id}' ")
            print(f"Project '{id}' : creating...")
            proj = self(id)
            proj.setUp = setUp
            proj.v = v
            print(df + ": setUp....")
            setUp(proj)
            print(df + ": ok")
            StudyProjectEnv.saveProject(proj)
            return proj

        # "project-"+Git.toBrancheName(id)
        if Git.checkBranch("project-" + Git.toBrancheName(id)):
            Git.goToBranch("project-" + Git.toBrancheName(id))
            project = StudyProjectEnv.getProject(id, setUp)
            # setUpMd5=Utils.Hash.function_md5(setUp)
            if project.setUp == "outdated":
                return create_project()
            if project is not None:
                print(f"Project '{id}' : loaded")
                return project
            print(f"Project {id} not load !!!")
            return
            # load projectloaded")
            return self.proj[id]
        return create_project()

    def getOrCreateStudy(self, id, setUp=None, data=None):
        if id in self.studies:
            print(f"Study '{id}' : loaded")
            return self.studies[id]
        df = " " * len(f"Study '{id}' ")
        print(f"Study '{id}' : creating...")
        self.studies[id] = Study(id, data=data)
        if setUp is not None:
            print(df + ": setUp....")
            setUp(self.studies[id])
            print(df + ": ok")


__all__ = ["StudyProject", "Data"]
