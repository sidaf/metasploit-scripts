# Original work Copyright (c) 2016, Carlos Perez <carlos_perez[at]darkoperator.com>
# Modified work Copyright (c) 2017 Sion Dafydd <sion.dafydd[at]gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted
# provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this list of conditions and
# the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright notice, this list of conditions
# and the following disclaimer in the documentation and/or other materials provided with the
# distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

module Msf
  class Plugin::Project < Msf::Plugin

    class ProjectCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      # Set name for command dispatcher
      def name
        'Project'
      end

      # Define Commands
      def commands
        {
            'project' => 'Command for managing projects.',
        }
      end

      def cmd_project(*args)
        # variable
        project_name = ''
        create = false
        delete = false
        history = false
        switch = false
        archive = false
        arch_path = ::File.join(Msf::Config.log_directory, 'archives')
        # Define options
        opts = Rex::Parser::Arguments.new(
            '-c' => [false, 'Create a new Metasploit project and sets logging for it'],
            '-d' => [false, 'Delete a project created by the plugin'],
            '-s' => [false, 'Switch to a project created by the plugin'],
            '-a' => [false, 'Export all history and DB and archive it in to a zip file for current project'],
            '-p' => [true, 'Path to save archive, if none provide default ~/.msf4/archives will be used'],
            '-r' => [false, 'Create time stamped RC files of Meterpreter Sessions and console history for current project'],
            '-ph' => [false, 'Generate resource files for sessions and console. Generate time stamped session logs for current project'],
            '-l' => [false, 'List projects created by plugin'],
            '-h' => [false, 'Command Help']
        )
        opts.parse(args) do |opt, idx, val|
          case opt
            when '-p'
              if ::File.directory?(val)
                arch_path = val
              else
                print_error('Path provided for archive does not exists!')
                return
              end
            when '-d'
              delete = true
            when '-s'
              switch = true
            when '-a'
              archive = true
            when '-c'
              create = true
            when '-r'
              make_console_rc
              make_sessions_rc
            when '-h'
              print_line(opts.usage)
              return
            when '-l'
              list
              return
            when '-ph'
              history = true
            else
              project_name = val.gsub(' ', '_').chomp
          end
        end
        if project_name and create
          project_create(project_name)
        elsif project_name and delete
          project_delete(project_name)
        elsif project_name and switch
          project_switch(project_name)
        elsif archive
          project_archive(arch_path)
        elsif history
          project_history
        else
          list
        end
      end

      def project_delete(project_name)
        # Check if project exists
        if project_list.include?(project_name)
          current_workspace = framework.db.workspace.name
          if current_workspace == project_name
            driver.init_ui(driver.input, Rex::Ui::Text::Output::Stdio.new)
          end
          workspace = framework.db.find_workspace(project_name)
          if workspace.default?
            workspace.destroy
            workspace = framework.db.add_workspace(project_name)
            print_line('Deleted and recreated the default workspace')
          else
            # switch to the default workspace if we're about to delete the current one
            framework.db.workspace = framework.db.default_workspace if framework.db.workspace.name == workspace.name
            # now destroy the named workspace
            workspace.destroy
            print_line("Deleted workspace: #{project_name}")
          end
          project_path = ::File.join(Msf::Config.log_directory, 'projects', project_name)
          ::FileUtils.rm_rf(project_path)
          print_line("Project folder #{project_path} has been deleted")
        else
          print_error('Project was not found on list of projects!')
        end
        return true
      end

      # Switch to another project created by the plugin
      def project_switch(project_name)
        # Check if project exists
        if project_list.include?(project_name)
          print_line("Switching to #{project_name}")
          # Disable spooling for current
          driver.init_ui(driver.input, Rex::Ui::Text::Output::Stdio.new)

          # Switch workspace
          workspace = framework.db.find_workspace(project_name)
          framework.db.workspace = workspace
          print_line("Workspace: #{workspace.name}")

          # Spool
          spool_path = ::File.join(Msf::Config.log_directory, 'projects', framework.db.workspace.name)
          spool_file = ::File.join(spool_path, "#{project_name}_spool.log")

          # Start spooling for new workspace
          driver.init_ui(driver.input, Rex::Ui::Text::Output::Tee.new(spool_file))
          print_line("Spooling to file #{spool_file}...")
          print_line("Successfully migrated to #{project_name}")

        else
          print_error('Project was not found on list of projects!')
        end
        return true
      end

      # List current projects created by the plugin
      def list
        current_workspace = framework.db.workspace.name
        print_line('List of projects:')
        project_list.each do |p|
          if current_workspace == p
            print_line("\t* #{p}")
          else
            print_line("\t#{p}")
          end
        end
        return true
      end

      # Archive project in to a zip file
      def project_archive(archive_path)
        # Set variables for options
        project_name = framework.db.workspace.name
        project_path = ::File.join(Msf::Config.log_directory, 'projects', project_name)
        archive_name = "#{project_name}_#{::Time.now.strftime('%Y%m%d.%M%S')}.zip"
        db_export_name = "#{project_name}_#{::Time.now.strftime('%Y%m%d.%M%S')}.xml"
        db_out = ::File.join(project_path, db_export_name)
        format = 'xml'
        print_line("Exporting DB Workspace #{project_name}")
        exporter = Msf::DBManager::Export.new(framework.db.workspace)
        exporter.send("to_#{format}_file".intern, db_out) do |mtype, mstatus, mname|
          if mtype == :status
            if mstatus == 'start'
              print_line("  >> Starting export of #{mname}")
            end
            if mstatus == 'complete'
              print_line("  >> Finished export of #{mname}")
            end
          end
        end
        print_line("Finished export of workspace #{framework.db.workspace.name} to #{db_out} [ #{format} ]...")
        print_line("Disabling spooling for #{project_name}")
        driver.init_ui(driver.input, Rex::Ui::Text::Output::Stdio.new)
        print_line('Spooling disabled for archiving')
        archive_full_path = ::File.join(archive_path, archive_name)
        make_console_rc
        make_sessions_rc
        make_sessions_logs
        compress(project_path, archive_full_path)
        print_line("MD5 for archive is #{digestmd5(archive_full_path)}")
        # Spool
        spool_path = ::File.join(Msf::Config.log_directory, 'projects', framework.db.workspace.name)
        spool_file = ::File.join(spool_path, "#{project_name}_spool.log")
        print_line('Spooling re-enabled')
        # Start spooling for new workspace
        driver.init_ui(driver.input, Rex::Ui::Text::Output::Tee.new(spool_file))
        print_line("Spooling to file #{spool_file}...")
        return true
      end

      # Export Command History for Sessions and Console
      #-------------------------------------------------------------------------------------------
      def project_history
        make_console_rc
        make_sessions_rc
        make_sessions_logs
        return true
      end

      # Create a new project Workspace and enable logging
      #-------------------------------------------------------------------------------------------
      def project_create(project_name)
        # Make sure that proper values where provided
        spool_path = ::File.join(Msf::Config.log_directory, 'projects', project_name)
        ::FileUtils.mkdir_p(spool_path)
        spool_file = ::File.join(spool_path, "#{project_name}_spool.log")
        if framework.db and framework.db.active
          print_line("Creating DB Workspace named #{project_name}")
          workspace = framework.db.add_workspace(project_name)
          framework.db.workspace = workspace
          print_line("Added workspace: #{workspace.name}")
          driver.init_ui(driver.input, Rex::Ui::Text::Output::Tee.new(spool_file))
          print_line("Spooling to file #{spool_file}...")
        else
          print_error('A database most be configured and connected to create a project')
        end

        return true
      end

      # Method for creating a console resource file from all commands entered in the console
      #-------------------------------------------------------------------------------------------
      def make_console_rc
        # Set RC file path and file name
        rc_file = "#{framework.db.workspace.name}_#{::Time.now.strftime('%Y%m%d.%M%S')}.rc"
        consonle_rc_path = ::File.join(Msf::Config.log_directory, 'projects', framework.db.workspace.name)
        rc_full_path = ::File.join(consonle_rc_path, rc_file)

        # Create folder
        ::FileUtils.mkdir_p(consonle_rc_path)
        con_rc = ''
        framework.db.workspace.events.each do |e|
          if not e.info.nil? and e.info.has_key?(:command) and not e.info.has_key?(:session_type)
            con_rc << "# command executed at #{e.created_at}\n"
            con_rc << "#{e.info[:command]}\n"
          end
        end

        # Write RC console file
        print_line("Writing Console RC file to #{rc_full_path}")
        file_write(rc_full_path, con_rc)
        print_line('RC file written')

        return rc_full_path
      end

      # Method for creating individual rc files per session using the session uuid
      #-------------------------------------------------------------------------------------------
      def make_sessions_rc
        sessions_uuids = []
        sessions_info = []
        info = ''
        rc_file = ''
        rc_file_name = ''
        rc_list =[]

        framework.db.workspace.events.each do |e|
          if not e.info.nil? and e.info.has_key?(:command) and e.info[:session_type] =~ /meter/
            if e.info[:command] != 'load stdapi'
              if not sessions_uuids.include?(e.info[:session_uuid])
                sessions_uuids << e.info[:session_uuid]
                sessions_info << {:uuid => e.info[:session_uuid],
                                  :type => e.info[:session_type],
                                  :id => e.info[:session_id],
                                  :info => e.info[:session_info]}
              end
            end
          end
        end

        sessions_uuids.each do |su|
          sessions_info.each do |i|
            if su == i[:uuid]
              print_line("Creating RC file for Session #{i[:id]}")
              rc_file_name = "#{framework.db.workspace.name}_session_#{i[:id]}_#{::Time.now.strftime('%Y%m%d.%M%S')}.rc"
              i.each do |k, v|
                info << "#{k.to_s}: #{v.to_s} "
              end
              break
            end
          end
          rc_file << "# Info: #{info}\n"
          info = ''
          framework.db.workspace.events.each do |e|
            if not e.info.nil? and e.info.has_key?(:command) and e.info.has_key?(:session_uuid)
              if e.info[:session_uuid] == su
                rc_file << "# command executed at #{e.created_at}\n"
                rc_file << "#{e.info[:command]}\n"
              end
            end
          end
          # Set RC file path and file name
          consonle_rc_path = ::File.join(Msf::Config.log_directory, 'projects', framework.db.workspace.name)
          rc_full_path = ::File.join(consonle_rc_path, rc_file_name)
          print_line("Saving RC file to #{rc_full_path}")
          file_write(rc_full_path, rc_file)
          rc_file = ''
          print_line('RC file written')
          rc_list << rc_full_path
        end

        return rc_list
      end

      # Method for exporting session history with output
      #-------------------------------------------------------------------------------------------
      def make_sessions_logs
        sessions_uuids = []
        sessions_info = []
        info = ''
        hist_file = ''
        hist_file_name = ''
        log_list = []

        # Create list of sessions with base info
        framework.db.workspace.events.each do |e|
          if not e.info.nil? and e.info[:session_type] =~ /shell/ or e.info[:session_type] =~ /meter/
            if e.info[:command] != 'load stdapi'
              if not sessions_uuids.include?(e.info[:session_uuid])
                sessions_uuids << e.info[:session_uuid]
                sessions_info << {:uuid => e.info[:session_uuid],
                                  :type => e.info[:session_type],
                                  :id => e.info[:session_id],
                                  :info => e.info[:session_info]}
              end
            end
          end
        end

        sessions_uuids.each do |su|
          sessions_info.each do |i|
            if su == i[:uuid]
              print_line("Exporting Session #{i[:id]} history")
              hist_file_name = "#{framework.db.workspace.name}_session_#{i[:id]}_#{::Time.now.strftime('%Y%m%d.%M%S')}.log"
              i.each do |k, v|
                info << "#{k.to_s}: #{v.to_s} "
              end
              break
            end
          end
          hist_file << "# Info: #{info}\n"
          info = ''
          framework.db.workspace.events.each do |e|
            if not e.info.nil? and e.info.has_key?(:command) or e.info.has_key?(:output)
              if e.info[:session_uuid] == su
                if e.info.has_key?(:command)
                  hist_file << "#{e.updated_at}\n"
                  hist_file << "#{e.info[:command]}\n"
                elsif e.info.has_key?(:output)
                  hist_file << "#{e.updated_at}\n"
                  hist_file << "#{e.info[:output]}\n"
                end
              end
            end
          end

          # Set RC file path and file name
          session_hist_path = ::File.join(Msf::Config.log_directory, 'projects', framework.db.workspace.name)
          session_hist_fullpath = ::File.join(session_hist_path, hist_file_name)

          # Create folder
          ::FileUtils.mkdir_p(session_hist_path)

          print_line("Saving log file to #{session_hist_fullpath}")
          file_write(session_hist_fullpath, hist_file)
          hist_file = ''
          print_line('Log file written')
          log_list << session_hist_fullpath
        end

        return log_list
      end

      # Compress a given folder given it's path
      #-------------------------------------------------------------------------------------------
      def compress(path, archive)
        require 'zip/zip'
        require 'zip/zipfilesystem'

        path.sub!(%r[/$], '')
        ::Zip::ZipFile.open(archive, 'w') do |zipfile|
          Dir["#{path}/**/**"].reject { |f| f==archive }.each do |file|
            print_line("Adding #{file} to archive")
            zipfile.add(file.sub(path+'/', ''), file)
          end
        end
        print_line("All files saved to #{archive}")
      end

      # Method to write string to file
      def file_write(file2wrt, data2wrt)
        if not ::File.exists?(file2wrt)
          ::FileUtils.touch(file2wrt)
        end

        output = ::File.open(file2wrt, 'a')
        data2wrt.each_line do |d|
          output.puts(d)
        end
        output.close
      end

      # Method to create MD5 of given file
      def digestmd5(file2md5)
        if not ::File.exists?(file2md5)
          raise "File #{file2md5} does not exists!"
        else
          require 'digest/md5'
          chksum = nil
          chksum = Digest::MD5.hexdigest(::File.open(file2md5, 'rb') { |f| f.read })
          return chksum
        end
      end

      # Method that returns a hash of projects
      def project_list
        project_folders = Dir::entries(::File.join(Msf::Config.log_directory, 'projects'))
        projects = []
        framework.db.workspaces.each do |s|
          if project_folders.include?(s.name)
            projects << s.name
          end
        end
        return projects
      end

    end

    def initialize(framework, opts)
      super
      if framework.db and framework.db.active
        add_console_dispatcher(ProjectCommandDispatcher)

        archive_path = ::File.join(Msf::Config.log_directory, 'archives')
        project_paths = ::File.join(Msf::Config.log_directory, 'projects')

        # Create project folder if first run
        if not ::File.directory?(project_paths)
          ::FileUtils.mkdir_p(project_paths)
        end

        # Create archive folder if first run
        if not ::File.directory?(archive_path)
          ::FileUtils.mkdir_p(archive_path)
        end

        print_line 'Version 1.4.1'
        print_line 'Project plugin loaded.'
      else
        print_error('This plugin requires the framework to be connected to a Database!')
      end
    end

    def cleanup
      remove_console_dispatcher('Project')
    end

    def name
      'project'
    end

    def desc
      'Plugin for managing projects.'
    end

    protected
  end
end
