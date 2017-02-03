# Ruby license. Copyright (C)2004-2008 Joel VanderWerf.
# Contact mailto:vjoel@users.sourceforge.net.
#
# A lightweight, non-drifting, self-correcting timer. Average error is bounded
# as long as, on average, there is enough time to complete the work done, and
# the timer is checked often enough. It is lightweight in the sense that no
# threads are created. Can be used either as an internal iterator (Timer.every)
# or as an external iterator (Timer.new). Obviously, the GC can cause a
# temporary slippage.
#
# Simple usage:
#
#   require 'timer'
#
#   Timer.every(0.1, 0.5) { |elapsed| puts elapsed }
#
#   timer = Timer.new(0.1)
#   5.times do
#     puts timer.elapsed
#     timer.wait
#   end 
#
class Timer
  # Yields to the supplied block every +period+ seconds. The value yielded is
  # the total elapsed time (an instance of +Time+). If +expire+ is given, then
  # #every returns after that amount of elapsed time.
  def Timer.every(period, expire = nil)
    target = time_start = Time.now
    loop do
      elapsed = Time.now - time_start
      break if expire and elapsed > expire
      yield elapsed
      target += period
      error = target - Time.now
      sleep error if error > 0
    end
  end
  
  # Make a Timer that can be checked when needed, using #wait or #if_ready. The
  # advantage over Timer.every is that the timer can be checked on separate
  # passes through a loop.
  def initialize(period = 1)
    @period = period
    restart
  end
  
  attr_accessor :period
  
  # Call this to restart the timer after a period of inactivity (e.g., the user
  # hits the pause button, and then hits the go button).
  def restart
    @target = @time_start = Time.now
  end
  
  # Time on timer since instantiation or last #restart.
  def elapsed
    Time.now - @time_start
  end
  
  # Wait for the next cycle, if time remains in the current cycle. Otherwise,
  # return immediately to caller.
  def wait(per = nil)
    @target += per || @period
    error = @target - Time.now
    sleep error if error > 0
    true
  end
  
  # Yield to the block if no time remains in cycle. Otherwise, return
  # immediately to caller
  def if_ready
    error = @target + @period - Time.now
    if error <= 0
      @target += @period
      elapsed = Time.now - @time_start
      yield elapsed
    end
  end
end
