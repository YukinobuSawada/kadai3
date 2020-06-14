class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

          validates_uniqueness_of :username
          validates_presence_of :username

            def self.find_first_by_auth_conditions(warden_conditions)
            	conditions = warden_conditions.dup
            	if login = conditions.delete(:login)
            		where(conditions).where(["username = :value", { :value => username }]).first
            	else
            		 where(conditions).first
            		end
            	end

    

          def email_required?
          	false
          end
           def email_changed?
           	false
           end



end
